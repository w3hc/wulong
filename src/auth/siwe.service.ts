import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { Injectable } from '@nestjs/common';
import { SiweMessage } from 'siwe';
import { KeyDerivationService } from '../keys/key-derivation.service';

// A nonce is hex(issuedAt u64be || random || tag): 64 hex characters
const RANDOM_BYTES = 8;
const TAG_BYTES = 16;
const NONCE_PATTERN = /^[0-9a-f]{64}$/;

@Injectable()
export class SiweService {
  // Nonces seen by a verification attempt, in insertion order, with the
  // time they can be forgotten. Pending nonces are not stored at all.
  private readonly used = new Map<string, number>();

  // Nonce expires after 5 minutes
  private readonly NONCE_TTL = 5 * 60 * 1000;

  // Tolerated clock drift between the client and the server
  private readonly CLOCK_SKEW = 30 * 1000;

  // Hosts (with port) of the UIs allowed to request a signature
  private readonly domains: string[];

  // Origin schemes allowed; EIP-4361 treats a missing scheme as https
  private readonly schemes: string[];

  // Chains a message may name: Ethereum mainnet and Base by default
  private readonly chainIds: number[];

  // Used only when key derivation is unavailable, which aborts startup in
  // production: nonces then do not survive a restart or span instances
  private readonly fallbackKey = randomBytes(32);

  constructor(private readonly keys: KeyDerivationService) {
    const domains = (process.env.SIWE_DOMAIN ?? '')
      .split(',')
      .map((domain) => domain.trim())
      .filter(Boolean);
    if (!domains.length && process.env.NODE_ENV === 'production') {
      throw new Error('SIWE_DOMAIN must be set in production');
    }
    this.domains = domains.length ? domains : ['localhost', 'localhost:3000'];
    this.schemes =
      process.env.NODE_ENV === 'production' ? ['https'] : ['https', 'http'];
    this.chainIds = (process.env.SIWE_CHAIN_IDS || '1,8453')
      .split(',')
      .map((chainId) => Number(chainId.trim()));
  }

  /**
   * Generate a nonce bound to the address that will sign with it.
   * The nonce carries its issue time and an HMAC under an enclave-derived
   * key, so nothing is stored until it is used and pending nonces cannot
   * exhaust memory.
   */
  generateNonce(address: string): string {
    const issuedAt = Buffer.alloc(8);
    issuedAt.writeBigUInt64BE(BigInt(Date.now()));
    const random = randomBytes(RANDOM_BYTES);
    return Buffer.concat([
      issuedAt,
      random,
      this.tag(issuedAt, random, address),
    ]).toString('hex');
  }

  /**
   * Verify SIWE message and signature
   * Returns the Ethereum address if valid, null otherwise
   */
  async verifySignature(
    message: string,
    signature: string,
  ): Promise<string | null> {
    try {
      const siweMessage = new SiweMessage(message);

      const createdAt = this.checkNonce(siweMessage.nonce, siweMessage.address);
      if (createdAt === null) {
        return null; // Forged, or issued to another address
      }

      const now = Date.now();
      if (now - createdAt > this.NONCE_TTL) {
        return null; // Nonce expired
      }

      // Single-use nonce: consumed by any verification attempt
      this.forgetExpiredNonces(now);
      if (this.used.has(siweMessage.nonce)) {
        return null;
      }
      this.used.set(siweMessage.nonce, now + this.NONCE_TTL);

      // Issued At must fall between nonce creation and now
      const issuedAt = Date.parse(siweMessage.issuedAt ?? '');
      if (
        Number.isNaN(issuedAt) ||
        issuedAt < createdAt - this.CLOCK_SKEW ||
        issuedAt > now + this.CLOCK_SKEW
      ) {
        return null;
      }

      if (
        !this.domains.includes(siweMessage.domain) ||
        !this.schemes.includes(siweMessage.scheme ?? 'https')
      ) {
        return null;
      }

      // The URI must point at an allowed origin, not only the domain line
      const uri = new URL(siweMessage.uri);
      if (
        !this.schemes.includes(uri.protocol.slice(0, -1)) ||
        !this.domains.includes(uri.host) ||
        !this.chainIds.includes(siweMessage.chainId)
      ) {
        return null;
      }

      // Enforces signature, domain, nonce, Expiration Time and Not Before
      const fields = await siweMessage.verify({
        signature,
        domain: siweMessage.domain,
        nonce: siweMessage.nonce,
        time: new Date(now).toISOString(),
      });

      return fields.data.address;
    } catch {
      // Verification failed - don't log the error details in production
      // to avoid leaking information about why verification failed
      return null;
    }
  }

  /**
   * Checks a nonce's tag against the address signing with it.
   * @returns The nonce's issue time, or null if the tag does not match
   */
  private checkNonce(nonce: string, address: string): number | null {
    if (!NONCE_PATTERN.test(nonce)) {
      return null;
    }
    const bytes = Buffer.from(nonce, 'hex');
    const issuedAt = bytes.subarray(0, 8);
    const random = bytes.subarray(8, 8 + RANDOM_BYTES);
    const tag = bytes.subarray(8 + RANDOM_BYTES);
    if (!timingSafeEqual(tag, this.tag(issuedAt, random, address))) {
      return null;
    }
    return Number(issuedAt.readBigUInt64BE());
  }

  // Fixed-length fields first, so the address needs no length prefix
  private tag(issuedAt: Buffer, random: Buffer, address: string): Buffer {
    const data = Buffer.concat([
      issuedAt,
      random,
      Buffer.from(address.toLowerCase(), 'utf-8'),
    ]);
    const mac = this.keys.isAvailable()
      ? this.keys.macSiweNonce(data)
      : createHmac('sha256', this.fallbackKey).update(data).digest();
    return mac.subarray(0, TAG_BYTES);
  }

  /**
   * Entries are inserted with the same lifetime, so the oldest come first
   * and pruning stops at the first live one.
   */
  private forgetExpiredNonces(now: number): void {
    for (const [nonce, forgetAt] of this.used) {
      if (forgetAt > now) {
        return;
      }
      this.used.delete(nonce);
    }
  }
}
