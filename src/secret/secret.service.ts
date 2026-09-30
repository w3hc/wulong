import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  HttpException,
  HttpStatus,
  Logger,
  OnModuleInit,
  ServiceUnavailableException,
} from '@nestjs/common';
import { getBytes, hexlify, isAddress } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { createHash, randomBytes } from 'crypto';
import { TeePlatformService } from '../attestation/tee-platform.service';
import { buildReportData } from '../attestation/report-data';
import { KeyDerivationService } from '../keys/key-derivation.service';
import { RelayerService } from '../relayer/relayer.service';
import { TeeTlsService } from '../tls/tee-tls.service';
import { AttestationResponseDto } from './dto/attestation-response.dto';
import {
  KEM_CIPHERTEXT_LENGTH,
  MLKEM_PUBLIC_KEY_LENGTH,
  MlKemEncryptionService,
  MultiRecipientEncryptedPayload,
  WRAPPED_KEY_LENGTH,
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
 *
 * When the relayer anchors, every write is committed on chain before it
 * replaces the chest, and the chest is checked against the anchor at boot, so
 * it cannot be rolled back to an older copy.
 */
@Injectable()
export class SecretService implements OnModuleInit {
  private readonly logger = new Logger(SecretService.name);
  private readonly secretPath: string;
  private readonly pendingPath: string;
  private readonly maxBytes: number;
  private writeQueue: Promise<unknown> = Promise.resolve();
  private anchoredSeq = 0n;

  constructor(
    private readonly teePlatformService: TeePlatformService,
    private readonly mlkemEncryptionService: MlKemEncryptionService,
    private readonly keys: KeyDerivationService,
    private readonly tls: TeeTlsService,
    private readonly relayer: RelayerService,
  ) {
    this.secretPath =
      process.env.CHEST_PATH ?? path.join(process.cwd(), 'chest.json');
    this.pendingPath = `${this.secretPath}.pending`;
    this.maxBytes = Number(
      process.env.CHEST_MAX_BYTES ?? DEFAULT_CHEST_MAX_BYTES,
    );
  }

  /**
   * Checks the chest against the on-chain anchor: it must be the last
   * anchored version, or the pending one if a crash hit between anchoring and
   * renaming. A chest that was never anchored is anchored as it is.
   * @throws Error if the chest does not match the anchor
   */
  async onModuleInit(): Promise<void> {
    const anchor = await this.relayer.getLatestAnchor();
    if (!anchor) {
      return;
    }

    const chest = await readIfExists(this.secretPath);
    if (anchor.seq === 0n) {
      if (chest) {
        await this.relayer.anchorChest(commitment(chest), 1n);
        this.anchoredSeq = 1n;
        this.logger.log('Anchored the existing chest for the first time');
      }
      return;
    }

    this.anchoredSeq = anchor.seq;
    if (chest && commitment(chest) === anchor.root) {
      await fs.promises.rm(this.pendingPath, { force: true });
      return;
    }
    const pending = await readIfExists(this.pendingPath);
    if (pending && commitment(pending) === anchor.root) {
      await fs.promises.rename(this.pendingPath, this.secretPath);
      this.logger.log('Recovered the anchored chest from its pending write');
      return;
    }
    throw new Error(
      `The chest does not match anchor ${anchor.seq}: it was rolled back or altered outside the enclave`,
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

    const version = encryptedPayload.version ?? 1;
    if (version !== 1 && version !== 2) {
      throw new BadRequestException('Unsupported encrypted payload version');
    }

    const ciphertextLength =
      KEM_CIPHERTEXT_LENGTH + WRAPPED_KEY_LENGTH[version];
    for (const recipient of encryptedPayload.recipients) {
      if (
        Buffer.from(recipient.publicKey, 'base64').length !==
        MLKEM_PUBLIC_KEY_LENGTH
      ) {
        throw new BadRequestException(
          `Invalid ML-KEM public key size: expected ${MLKEM_PUBLIC_KEY_LENGTH} bytes`,
        );
      }
      if (
        Buffer.from(recipient.ciphertext, 'base64').length !== ciphertextLength
      ) {
        throw new BadRequestException(
          `Invalid ML-KEM ciphertext size: expected ${ciphertextLength} bytes`,
        );
      }
    }

    // A chest the server cannot decrypt would only ever answer 400 on access
    const serverPublicKey = this.mlkemEncryptionService.getPublicKey();
    if (
      !encryptedPayload.recipients.some((r) => r.publicKey === serverPublicKey)
    ) {
      throw new BadRequestException(
        'Invalid encrypted payload: the server must be one of the recipients',
      );
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
          'Invalid Ethereum address in publicAddresses',
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
   * @throws NotFoundException if slot doesn't exist or caller is not an owner
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

    // A slot the caller does not own answers like one that does not exist,
    // so callers cannot probe which slots are in use
    const entry = Object.hasOwn(secretData, slot)
      ? secretData[slot]
      : undefined;
    if (!entry?.publicAddresses.includes(callerAddress.toLowerCase())) {
      throw new NotFoundException('Slot not found');
    }

    // Decrypt the secret using server's ML-KEM private key
    try {
      const plaintextSecret = this.mlkemEncryptionService.decryptMultiRecipient(
        entry.encryptedPayload,
      );
      return plaintextSecret;
    } catch {
      throw new BadRequestException('Failed to decrypt secret');
    }
  }

  /**
   * Generates a TEE attestation whose `report_data` commits to Wulong's public
   * keys, to the TLS certificate served from inside the enclave, and to the
   * client's nonce, so a client can check that the returned ML-KEM key is the
   * one held by the attested code and that its TLS session ends in it.
   * @param nonce Optional 32-byte client challenge for freshness
   * @returns Attestation report, the committed keys, the `report_data`, the
   * signed key manifest and the identity and relayer `GetKey` signature
   * chains
   * @throws ServiceUnavailableException if the keys have not been derived
   */
  async getAttestation(nonce?: Buffer): Promise<AttestationResponseDto> {
    const mlkemPublicKey = this.keys.getMlKemPublicKey();
    const identityPublicKey = this.keys.getIdentityPublicKey();
    const relayerAddress = this.keys.getRelayerAddress();
    const relayerPublicKey = this.keys.getRelayerPublicKey();
    const keyManifest = this.keys.getKeyManifest();
    if (
      !mlkemPublicKey ||
      !identityPublicKey ||
      !relayerAddress ||
      !relayerPublicKey ||
      !keyManifest
    ) {
      throw new ServiceUnavailableException('Encryption keys are unavailable');
    }

    const tlsCertificateDer = this.tls.getLeafCertificateDer() ?? undefined;
    const reportData = buildReportData(
      {
        mlkemPublicKey,
        relayer: getBytes(relayerAddress),
        identityPublicKey,
        tlsCertificateDer,
      },
      nonce,
    );
    const attestation =
      await this.teePlatformService.generateAttestationReport(reportData);

    return {
      platform: attestation.platform,
      report: attestation.report,
      measurements: attestation.measurements,
      eventLog: attestation.eventLog,
      timestamp: attestation.timestamp,
      mlkemPublicKey: Buffer.from(mlkemPublicKey).toString('base64'),
      identityPublicKey: `0x${Buffer.from(identityPublicKey).toString('hex')}`,
      relayerAddress,
      relayerPublicKey: hexlify(relayerPublicKey),
      tlsCertificate: tlsCertificateDer
        ? Buffer.from(tlsCertificateDer).toString('base64')
        : undefined,
      reportData: `0x${reportData.toString('hex')}`,
      keyManifest,
      identitySignatureChain: this.keys
        .getIdentitySignatureChain()
        .map((link) => hexlify(link)),
      relayerSignatureChain: this.keys
        .getRelayerSignatureChain()
        .map((link) => hexlify(link)),
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
   * a partially written chest behind. When anchoring, the temp file is
   * anchored on chain before the rename.
   * @param data The secret data to save
   * @throws HttpException (507) if the chest would exceed CHEST_MAX_BYTES
   * @throws ServiceUnavailableException if the write cannot be anchored
   */
  private async saveSecret(data: SecretData): Promise<void> {
    const serialized = JSON.stringify(data, null, 2);
    if (Buffer.byteLength(serialized, 'utf-8') > this.maxBytes) {
      throw new HttpException(
        'Secret storage is full',
        HttpStatus.INSUFFICIENT_STORAGE,
      );
    }

    const anchoring = this.relayer.isEnabled();
    const tmpPath = anchoring ? this.pendingPath : `${this.secretPath}.tmp`;
    try {
      await fs.promises.writeFile(tmpPath, serialized, {
        encoding: 'utf-8',
        flush: true,
      });
    } catch (error) {
      throw new Error(
        `Failed to save secret: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error },
      );
    }

    if (anchoring) {
      await this.anchor(commitment(Buffer.from(serialized, 'utf-8')));
    }

    try {
      await fs.promises.rename(tmpPath, this.secretPath);
    } catch (error) {
      throw new Error(
        `Failed to save secret: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { cause: error },
      );
    }
  }

  /**
   * Anchors the pending chest. A failed or timed-out transaction may still
   * have been included, so the anchor is read back before giving up.
   */
  private async anchor(root: string): Promise<void> {
    const seq = this.anchoredSeq + 1n;
    try {
      await this.relayer.anchorChest(root, seq);
      this.anchoredSeq = seq;
      return;
    } catch (error) {
      const latest = await this.relayer.getLatestAnchor().catch(() => null);
      if (latest?.root === root) {
        this.anchoredSeq = latest.seq;
        return;
      }
      if (latest) {
        this.anchoredSeq = latest.seq;
      }
      await fs.promises.rm(this.pendingPath, { force: true });
      this.logger.error(
        `Anchoring chest write ${seq} failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      throw new ServiceUnavailableException('Secret storage is unavailable');
    }
  }
}

/** The on-chain commitment to a version of the chest. */
function commitment(chest: Buffer): string {
  return `0x${createHash('sha256').update(chest).digest('hex')}`;
}

async function readIfExists(file: string): Promise<Buffer | null> {
  try {
    return await fs.promises.readFile(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}
