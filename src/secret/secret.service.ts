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
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
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

const CHEST_ENTRY_VERSION = 3;
// Entries stored before owners were recorded: still readable, owned by none
const LEGACY_CHEST_ENTRY_VERSION = 2;

interface SecretEntry {
  version: typeof CHEST_ENTRY_VERSION | typeof LEGACY_CHEST_ENTRY_VERSION;
  encryptedPayload: MultiRecipientEncryptedPayload; // Multi-recipient encrypted data
  publicAddresses: string[]; // Authorized SIWE addresses
  owner?: string; // Lowercase address that stored the entry, from version 3
  mac: string; // Hex HMAC binding the slot, payload, addresses and owner (see entryMac)
}

const DEFAULT_CHEST_MAX_BYTES = 50 * 1024 * 1024;
const SLOT_PATTERN = /^[0-9a-f]{64}$/;

interface SecretData {
  [slot: string]: SecretEntry;
}

/**
 * Secret service for storing and accessing secrets with owner-based access control.
 *
 * Every entry carries a MAC under a key only the enclave holds, so an access
 * list edited on disk is rejected instead of opening the decryption oracle.
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
  private chest: Promise<SecretData> | null = null;
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
   * Verifies the chest against its anchor, then warns about entries that
   * fail authentication.
   * @throws Error if the chest does not match the anchor
   */
  async onModuleInit(): Promise<void> {
    await this.verifyAnchor();
    await this.reportUnauthenticatedEntries();
  }

  /**
   * Checks the chest against the on-chain anchor: it must be the last
   * anchored version, or the pending one if a crash hit between anchoring and
   * renaming. A chest that was never anchored is anchored as it is.
   * @throws Error if the chest does not match the anchor
   */
  private async verifyAnchor(): Promise<void> {
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
   * Counts the entries that fail authentication, such as chests written
   * before entries were versioned: they can no longer be accessed.
   */
  private async reportUnauthenticatedEntries(): Promise<void> {
    if (!this.mlkemEncryptionService.isAvailable()) {
      return;
    }
    const secretData = await this.getChest();
    const rejected = Object.entries(secretData).filter(
      ([slot, entry]) => !this.isAuthentic(slot, entry),
    ).length;
    if (rejected > 0) {
      this.logger.warn(
        `${rejected} chest entries fail authentication and cannot be accessed: they predate versioned entries or were altered outside the enclave`,
      );
    }
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
    await this.withWriteLock(() =>
      this.commit({
        [slot]: this.seal(
          slot,
          encryptedPayload,
          normalizedAddresses,
          callerAddress.toLowerCase(),
        ),
      }),
    );

    return slot;
  }

  /**
   * Accesses a secret if the caller is an owner.
   * Server performs ML-KEM decryption and returns plaintext.
   *
   * @param slot The slot identifier
   * @param callerAddress The address of the caller (from SIWE authentication)
   * @returns The decrypted secret (plaintext)
   * @throws NotFoundException if slot is malformed, doesn't exist or caller
   * is not an owner
   * @throws BadRequestException if decryption fails
   */
  async access(slot: string, callerAddress: string): Promise<string> {
    // Only generateSlot's output can exist, so nothing else reaches the
    // lookup, whatever the chest holds
    if (typeof slot !== 'string' || !SLOT_PATTERN.test(slot)) {
      throw new NotFoundException('Slot not found');
    }

    if (!callerAddress || !isAddress(callerAddress)) {
      throw new BadRequestException('Invalid caller address');
    }

    if (!this.mlkemEncryptionService.isAvailable()) {
      throw new BadRequestException(
        'ML-KEM encryption not configured on server',
      );
    }

    const secretData = await this.getChest();

    // A slot the caller does not own answers like one that does not exist,
    // so callers cannot probe which slots are in use. An entry that fails
    // authentication does not exist either: its access list is untrusted.
    const entry: unknown = Object.hasOwn(secretData, slot)
      ? secretData[slot]
      : undefined;
    if (
      !this.isAuthentic(slot, entry) ||
      !entry.publicAddresses.includes(callerAddress.toLowerCase())
    ) {
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
   * Builds a chest entry holding only the payload's known fields, with its
   * owner and MAC.
   */
  private seal(
    slot: string,
    payload: MultiRecipientEncryptedPayload,
    publicAddresses: string[],
    owner: string,
  ): SecretEntry {
    const encryptedPayload: MultiRecipientEncryptedPayload = {
      ...(payload.version === undefined ? {} : { version: payload.version }),
      recipients: payload.recipients.map(({ publicKey, ciphertext }) => ({
        publicKey,
        ciphertext,
      })),
      encryptedData: payload.encryptedData,
      iv: payload.iv,
      authTag: payload.authTag,
    };
    const entry = {
      version: CHEST_ENTRY_VERSION,
      encryptedPayload,
      publicAddresses,
      owner,
    };
    return { ...entry, mac: this.entryMac(slot, entry).toString('hex') };
  }

  /**
   * Checks an entry read from disk: it must be a current or legacy version
   * entry whose MAC matches its slot, payload, addresses and, from version
   * 3, owner. Malformed entries fail.
   */
  private isAuthentic(slot: string, entry: unknown): entry is SecretEntry {
    try {
      const candidate = entry as SecretEntry;
      if (
        (candidate?.version !== CHEST_ENTRY_VERSION ||
          typeof candidate.owner !== 'string') &&
        candidate?.version !== LEGACY_CHEST_ENTRY_VERSION
      ) {
        return false;
      }
      if (
        typeof candidate.mac !== 'string' ||
        !Array.isArray(candidate.publicAddresses)
      ) {
        return false;
      }
      const expected = this.entryMac(slot, candidate);
      const actual = Buffer.from(candidate.mac, 'hex');
      return (
        actual.length === expected.length && timingSafeEqual(actual, expected)
      );
    } catch {
      return false;
    }
  }

  /**
   * MACs the fixed-order JSON encoding of everything that decides who can
   * decrypt, delete or be charged for what: the entry version, the slot,
   * every payload field, the addresses and, from version 3, the owner.
   * Changing it makes every stored entry unreadable.
   */
  private entryMac(slot: string, entry: Omit<SecretEntry, 'mac'>): Buffer {
    const payload = entry.encryptedPayload;
    const fields: unknown[] = [
      'wulong-chest-entry',
      entry.version,
      slot,
      payload.version ?? 1,
      payload.recipients.map((r) => [r.publicKey, r.ciphertext]),
      payload.encryptedData,
      payload.iv,
      payload.authTag,
      entry.publicAddresses,
    ];
    if (entry.version === CHEST_ENTRY_VERSION) {
      fields.push(entry.owner);
    }
    return this.keys.macChestEntry(
      Buffer.from(JSON.stringify(fields), 'utf-8'),
    );
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
   * Returns the in-memory chest, reading the file the first time only. A
   * failed read is retried on the next call.
   */
  private getChest(): Promise<SecretData> {
    this.chest ??= this.loadSecret().catch((error: unknown) => {
      this.chest = null;
      throw error;
    });
    return this.chest;
  }

  /**
   * Writes the chest with `changes` applied, then makes it the in-memory
   * chest, so a failed write leaves memory as it was. A `null` change
   * removes its slot. Must run under the write lock.
   * @param changes The entries to set or remove, by slot
   */
  private async commit(changes: Record<string, SecretEntry | null>) {
    const next: SecretData = { ...(await this.getChest()) };
    for (const [slot, entry] of Object.entries(changes)) {
      if (entry) {
        next[slot] = entry;
      } else {
        delete next[slot];
      }
    }
    await this.saveSecret(next);
    this.chest = Promise.resolve(next);
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
