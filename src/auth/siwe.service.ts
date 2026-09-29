import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { SiweMessage, generateNonce } from 'siwe';

interface NonceEntry {
  nonce: string;
  address: string;
  createdAt: number;
}

@Injectable()
export class SiweService {
  // In-memory nonce storage (ephemeral, TEE-friendly)
  private readonly nonces = new Map<string, NonceEntry>();

  // Nonce expires after 5 minutes
  private readonly NONCE_TTL = 5 * 60 * 1000;

  // Upper bound on pending nonces, so the store cannot exhaust TEE memory
  private readonly MAX_NONCES = 10_000;

  // Tolerated clock drift between the client and the server
  private readonly CLOCK_SKEW = 30 * 1000;

  // Hosts (with port) of the UIs allowed to request a signature
  private readonly domains: string[];

  // Origin schemes allowed; EIP-4361 treats a missing scheme as https
  private readonly schemes: string[];

  constructor() {
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
  }

  /**
   * Generate a cryptographically secure random nonce
   * bound to the address that will sign with it.
   * Nonces are stored in-memory only (no persistence).
   * Once MAX_NONCES are pending, new requests are rejected
   * rather than evicting live nonces.
   */
  generateNonce(address: string): string {
    this.cleanExpiredNonces();
    if (this.nonces.size >= this.MAX_NONCES) {
      throw new HttpException(
        'Too many pending nonces',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const nonce = generateNonce();

    this.nonces.set(nonce, {
      nonce,
      address: address.toLowerCase(),
      createdAt: Date.now(),
    });

    return nonce;
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

      const nonceEntry = this.nonces.get(siweMessage.nonce);
      if (!nonceEntry) {
        return null; // Nonce not found or already used
      }

      // Single-use nonce: consumed by any verification attempt
      this.nonces.delete(siweMessage.nonce);

      const now = Date.now();
      if (now - nonceEntry.createdAt > this.NONCE_TTL) {
        return null; // Nonce expired
      }

      // Issued At must fall between nonce creation and now
      const issuedAt = Date.parse(siweMessage.issuedAt ?? '');
      if (
        Number.isNaN(issuedAt) ||
        issuedAt < nonceEntry.createdAt - this.CLOCK_SKEW ||
        issuedAt > now + this.CLOCK_SKEW
      ) {
        return null;
      }

      if (siweMessage.address.toLowerCase() !== nonceEntry.address) {
        return null; // Nonce issued to another address
      }

      if (
        !this.domains.includes(siweMessage.domain) ||
        !this.schemes.includes(siweMessage.scheme ?? 'https')
      ) {
        return null;
      }

      // Enforces signature, domain, nonce, Expiration Time and Not Before
      const fields = await siweMessage.verify({
        signature,
        domain: siweMessage.domain,
        nonce: nonceEntry.nonce,
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
   * Clean up expired nonces to prevent memory bloat
   */
  private cleanExpiredNonces(): void {
    const now = Date.now();
    for (const [nonce, entry] of this.nonces.entries()) {
      if (now - entry.createdAt > this.NONCE_TTL) {
        this.nonces.delete(nonce);
      }
    }
  }
}
