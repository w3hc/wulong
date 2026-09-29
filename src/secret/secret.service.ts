import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  HttpException,
  HttpStatus,
  ServiceUnavailableException,
} from '@nestjs/common';
import { isAddress } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { randomBytes } from 'crypto';
import { TeePlatformService } from '../attestation/tee-platform.service';
import { buildReportData } from '../attestation/report-data';
import { KeyDerivationService } from '../keys/key-derivation.service';
import { AttestationResponseDto } from './dto/attestation-response.dto';
import {
  MlKemEncryptionService,
  MultiRecipientEncryptedPayload,
} from '../encryption/mlkem-encryption.service';

interface SecretEntry {
  encryptedPayload: MultiRecipientEncryptedPayload; // Multi-recipient encrypted data
  publicAddresses: string[]; // Authorized SIWE addresses
}

const DEFAULT_CHEST_MAX_BYTES = 50 * 1024 * 1024;

interface SecretData {
  [slot: string]: SecretEntry;
}

/**
 * Secret service for storing and accessing secrets with owner-based access control.
 */
@Injectable()
export class SecretService {
  private readonly secretPath: string;
  private readonly maxBytes: number;
  private writeQueue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly teePlatformService: TeePlatformService,
    private readonly mlkemEncryptionService: MlKemEncryptionService,
    private readonly keys: KeyDerivationService,
  ) {
    this.secretPath =
      process.env.CHEST_PATH ?? path.join(process.cwd(), 'chest.json');
    this.maxBytes = Number(
      process.env.CHEST_MAX_BYTES ?? DEFAULT_CHEST_MAX_BYTES,
    );
  }

  /**
   * Stores a multi-recipient encrypted secret and returns a unique slot identifier.
   * @param encryptedPayload Multi-recipient ML-KEM encrypted payload (from w3pk)
   * @param publicAddresses Array of Ethereum addresses that can access this secret (via SIWE)
   * @param callerAddress The address of the caller (from SIWE authentication)
   * @returns The slot identifier
   * @throws BadRequestException if payload or addresses are invalid
   * @throws ForbiddenException if caller is not among publicAddresses
   */
  async store(
    encryptedPayload: MultiRecipientEncryptedPayload,
    publicAddresses: string[],
    callerAddress: string,
  ): Promise<string> {
    // Validate encryption service is available
    if (!this.mlkemEncryptionService.isAvailable()) {
      throw new BadRequestException(
        'ML-KEM encryption not configured on server. Contact administrator.',
      );
    }

    // Validate payload structure
    if (
      !encryptedPayload ||
      !encryptedPayload.recipients ||
      encryptedPayload.recipients.length === 0
    ) {
      throw new BadRequestException(
        'Invalid encrypted payload: must have at least one recipient',
      );
    }

    // Validate at least one recipient ciphertext size
    for (const recipient of encryptedPayload.recipients) {
      const ciphertextBytes = Buffer.from(recipient.ciphertext, 'base64');
      if (ciphertextBytes.length !== 1568 + 32) {
        throw new BadRequestException(
          `Invalid ML-KEM ciphertext size: ${ciphertextBytes.length} (expected ${1568 + 32})`,
        );
      }
    }

    // Validate addresses
    if (!publicAddresses || publicAddresses.length === 0) {
      throw new BadRequestException(
        'At least one public address must be provided',
      );
    }

    for (const address of publicAddresses) {
      if (!isAddress(address)) {
        throw new BadRequestException(
          `Invalid Ethereum address: ${String(address)}`,
        );
      }
    }

    // Normalize addresses
    const normalizedAddresses = publicAddresses.map((addr) =>
      addr.toLowerCase(),
    );

    if (
      !callerAddress ||
      !normalizedAddresses.includes(callerAddress.toLowerCase())
    ) {
      throw new ForbiddenException(
        'Store denied: caller must be one of publicAddresses',
      );
    }

    // Generate unique slot
    const slot = this.generateSlot();

    // Serialize read-modify-write so concurrent stores don't overwrite each other
    await this.withWriteLock(async () => {
      const secretData = await this.loadSecret();

      // Store the entry (encrypted at rest - quantum-safe!)
      secretData[slot] = {
        encryptedPayload,
        publicAddresses: normalizedAddresses,
      };

      await this.saveSecret(secretData);
    });

    return slot;
  }

  /**
   * Accesses a secret if the caller is an owner.
   * Server performs ML-KEM decryption and returns plaintext.
   *
   * @param slot The slot identifier
   * @param callerAddress The address of the caller (from SIWE authentication)
   * @returns The decrypted secret (plaintext)
   * @throws NotFoundException if slot doesn't exist
   * @throws ForbiddenException if caller is not an owner
   * @throws BadRequestException if decryption fails
   */
  async access(slot: string, callerAddress: string): Promise<string> {
    if (!slot || slot.trim().length === 0) {
      throw new BadRequestException('Slot cannot be empty');
    }

    if (!callerAddress || !isAddress(callerAddress)) {
      throw new BadRequestException('Invalid caller address');
    }

    if (!this.mlkemEncryptionService.isAvailable()) {
      throw new BadRequestException(
        'ML-KEM encryption not configured on server',
      );
    }

    // Load secret data
    const secretData = await this.loadSecret();

    // Check if slot exists
    const entry = secretData[slot];
    if (!entry) {
      throw new NotFoundException(`Slot not found: ${slot}`);
    }

    // Normalize caller address for comparison
    const normalizedCaller = callerAddress.toLowerCase();

    // Check if caller is an owner (SIWE authorization)
    if (!entry.publicAddresses.includes(normalizedCaller)) {
      throw new ForbiddenException(
        'Access denied: caller is not an owner of this secret',
      );
    }

    // Decrypt the secret using server's ML-KEM private key
    try {
      const plaintextSecret = this.mlkemEncryptionService.decryptMultiRecipient(
        entry.encryptedPayload,
      );
      return plaintextSecret;
    } catch (error) {
      throw new BadRequestException(
        `Failed to decrypt secret: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  /**
   * Generates a TEE attestation whose `report_data` commits to Wulong's public
   * keys and to the client's nonce, so a client can check that the returned
   * ML-KEM key is the one held by the attested code.
   * @param nonce Optional 32-byte client challenge for freshness
   * @returns Attestation report, the committed keys, the `report_data`, the
   * signed key manifest and the identity key's `GetKey` signature chain
   * @throws ServiceUnavailableException if the keys have not been derived
   */
  async getAttestation(nonce?: Buffer): Promise<AttestationResponseDto> {
    const mlkemPublicKey = this.keys.getMlKemPublicKey();
    const identityPublicKey = this.keys.getIdentityPublicKey();
    const keyManifest = this.keys.getKeyManifest();
    if (!mlkemPublicKey || !identityPublicKey || !keyManifest) {
      throw new ServiceUnavailableException('Encryption keys are unavailable');
    }

    const reportData = buildReportData(
      { mlkemPublicKey, identityPublicKey },
      nonce,
    );
    const attestation =
      await this.teePlatformService.generateAttestationReport(reportData);

    return {
      platform: attestation.platform,
      report: attestation.report,
      measurement: attestation.measurement,
      timestamp: attestation.timestamp,
      publicKey: attestation.publicKey,
      mlkemPublicKey: Buffer.from(mlkemPublicKey).toString('base64'),
      identityPublicKey: `0x${Buffer.from(identityPublicKey).toString('hex')}`,
      reportData: `0x${reportData.toString('hex')}`,
      keyManifest,
      identitySignatureChain: this.keys
        .getIdentitySignatureChain()
        .map((link) => `0x${Buffer.from(link).toString('hex')}`),
    };
  }

  /**
   * Generates a unique slot identifier.
   * @returns A random hex string
   */
  private generateSlot(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Runs `fn` after every previously queued write has settled.
   * @param fn The critical section
   * @returns The result of `fn`
   */
  private withWriteLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.writeQueue.then(fn, fn);
    this.writeQueue = run.catch(() => undefined);
    return run;
  }

  /**
   * Loads the secret data from the JSON file.
   * @returns The secret data object
   */
  private async loadSecret(): Promise<SecretData> {
    try {
      if (!fs.existsSync(this.secretPath)) {
        return {};
      }

      const data = await fs.promises.readFile(this.secretPath, 'utf-8');
      return JSON.parse(data) as SecretData;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return {};
      }
      throw new Error(
        `Failed to load secret: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error },
      );
    }
  }

  /**
   * Saves the secret data to the JSON file atomically: writes a flushed
   * temp file, then renames it over the chest, so a crash never leaves
   * a partially written chest behind.
   * @param data The secret data to save
   * @throws HttpException (507) if the chest would exceed CHEST_MAX_BYTES
   */
  private async saveSecret(data: SecretData): Promise<void> {
    const serialized = JSON.stringify(data, null, 2);
    if (Buffer.byteLength(serialized, 'utf-8') > this.maxBytes) {
      throw new HttpException(
        'Secret storage is full',
        HttpStatus.INSUFFICIENT_STORAGE,
      );
    }

    const tmpPath = `${this.secretPath}.tmp`;
    try {
      await fs.promises.writeFile(tmpPath, serialized, {
        encoding: 'utf-8',
        flush: true,
      });
      await fs.promises.rename(tmpPath, this.secretPath);
    } catch (error) {
      throw new Error(
        `Failed to save secret: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error },
      );
    }
  }
}
