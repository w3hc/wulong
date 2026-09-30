import { createHmac, hkdfSync } from 'crypto';
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import {
  SigningKey,
  Transaction,
  TransactionLike,
  TypedDataEncoder,
  computeAddress,
  getBytes,
  hexlify,
  sha256,
} from 'ethers';
import { createMlKem1024 } from 'mlkem';
import { DstackV1Client } from './dstack-v1.client';

export const MLKEM_DOMAIN = 'wulong/mlkem-1024/v1';
export const IDENTITY_DOMAIN = 'wulong/identity/v1';
export const RELAYER_DOMAIN = 'wulong/relayer/evm/v1';
export const CHEST_MAC_DOMAIN = 'wulong/chest-mac/v1';

const MLKEM_SEED_SALT = 'wulong';
const MLKEM_SEED_INFO = lengthPrefixed('wulong-mlkem-1024-seed-v1');
const CHEST_MAC_INFO = lengthPrefixed('wulong-chest-mac-v1');

export const KEY_MANIFEST_DOMAIN = { name: 'Wulong', version: '1' };
export const KEY_MANIFEST_TYPES = {
  KeyManifest: [
    { name: 'appId', type: 'address' },
    { name: 'mlkemPublicKeyHash', type: 'bytes32' },
    { name: 'relayer', type: 'address' },
    { name: 'epoch', type: 'uint64' },
  ],
};

export interface KeyManifest {
  appId: string;
  mlkemPublicKeyHash: string;
  relayer: string;
  epoch: number;
}

export interface SignedKeyManifest {
  manifest: KeyManifest;
  signature: string;
}

type MlKem = Awaited<ReturnType<typeof createMlKem1024>>;

/**
 * Derives Wulong's long-lived keys inside the enclave from the dstack KMS.
 *
 * Keys are a deterministic function of the app's KMS-held root key, so they
 * are never generated elsewhere, stored or passed through env, and every
 * instance of the same app gets the same keys. Private keys never leave this
 * service: callers get public keys, decapsulation, manifest signatures and
 * relayer transaction signatures and chest entry MACs.
 *
 * See docs/KEY_DERIVATION.md.
 */
@Injectable()
export class KeyDerivationService implements OnModuleInit {
  private readonly logger = new Logger(KeyDerivationService.name);
  private mlkem: MlKem | null = null;
  private mlkemPublicKey: Uint8Array | null = null;
  private mlkemSecretKey: Uint8Array | null = null;
  private identity: SigningKey | null = null;
  private identitySignatureChain: Uint8Array[] = [];
  private relayer: SigningKey | null = null;
  private relayerSignatureChain: Uint8Array[] = [];
  private keyManifest: SignedKeyManifest | null = null;
  private chestMacKey: Buffer | null = null;

  constructor(private readonly dstack: DstackV1Client) {}

  async onModuleInit(): Promise<void> {
    const production = process.env.NODE_ENV === 'production';

    if (production && this.dstack.isSimulator()) {
      throw new Error(
        'DSTACK_SIMULATOR_ENDPOINT must not be set in production: its keys are public',
      );
    }

    try {
      await this.derive();
    } catch (error) {
      if (production) {
        throw new Error('Key derivation from dstack v1 GetKey failed', {
          cause: error,
        });
      }
      this.logger.warn(
        'dstack v1 GetKey unavailable, encryption disabled. Run the dstack simulator and set DSTACK_SIMULATOR_ENDPOINT.',
      );
      return;
    }

    if (this.dstack.isSimulator()) {
      this.logger.warn('Keys derived from the dstack simulator (public root)');
    }
    this.logger.log(
      `Keys derived: ML-KEM-1024 ${Buffer.from(this.mlkemPublicKey!).toString('base64').substring(0, 32)}..., identity ${this.getIdentityAddress()}, relayer ${this.getRelayerAddress()}`,
    );
  }

  private async derive(): Promise<void> {
    const mlkemSource = await this.dstack.getKey(MLKEM_DOMAIN, 'ed25519');
    const seed = new Uint8Array(
      hkdfSync('sha256', mlkemSource.key, MLKEM_SEED_SALT, MLKEM_SEED_INFO, 64),
    );
    const mlkem = await createMlKem1024();
    const [publicKey, secretKey] = mlkem.deriveKeyPair(seed);
    mlkemSource.key.fill(0);
    seed.fill(0);

    const identity = await this.dstack.getKey(IDENTITY_DOMAIN, 'secp256k1');
    // hexlify leaves an immutable string copy of the key that fill(0) cannot
    // reach; ethers' SigningKey only takes the key as a hex string
    const signingKey = new SigningKey(hexlify(identity.key));
    identity.key.fill(0);

    // Used directly as the private key: v1 guarantees a valid secp256k1
    // scalar, unlike the v0 toViemAccountSecure adapter
    const relayer = await this.dstack.getKey(RELAYER_DOMAIN, 'secp256k1');
    const relayerKey = new SigningKey(hexlify(relayer.key));
    relayer.key.fill(0);

    const chestMac = await this.dstack.getKey(CHEST_MAC_DOMAIN, 'ed25519');
    const chestMacKey = Buffer.from(
      hkdfSync('sha256', chestMac.key, MLKEM_SEED_SALT, CHEST_MAC_INFO, 32),
    );
    chestMac.key.fill(0);

    const appId = await this.dstack.getAppId();

    this.mlkem = mlkem;
    this.mlkemPublicKey = publicKey;
    this.mlkemSecretKey = secretKey;
    this.identity = signingKey;
    this.identitySignatureChain = identity.signatureChain;
    this.relayer = relayerKey;
    this.relayerSignatureChain = relayer.signatureChain;
    this.chestMacKey = chestMacKey;
    this.keyManifest = this.signKeyManifest(appId);
  }

  isAvailable(): boolean {
    return (
      this.mlkemSecretKey !== null &&
      this.identity !== null &&
      this.chestMacKey !== null
    );
  }

  getMlKemPublicKey(): Uint8Array | null {
    return this.mlkemPublicKey;
  }

  decapsulate(ciphertext: Uint8Array): Uint8Array {
    if (!this.mlkem || !this.mlkemSecretKey) {
      throw new Error('ML-KEM keys not derived');
    }
    return this.mlkem.decap(ciphertext, this.mlkemSecretKey);
  }

  /**
   * HMAC-SHA256 under the chest MAC key, which authenticates chest entries
   * so the access list on disk cannot be altered outside the enclave.
   */
  macChestEntry(data: Uint8Array): Buffer {
    if (!this.chestMacKey) {
      throw new Error('Chest MAC key not derived');
    }
    return createHmac('sha256', this.chestMacKey).update(data).digest();
  }

  getIdentityAddress(): string | null {
    return this.identity ? computeAddress(this.identity.publicKey) : null;
  }

  /** Uncompressed secp256k1 identity public key, 65 bytes. */
  getIdentityPublicKey(): Uint8Array | null {
    return this.identity ? getBytes(this.identity.publicKey) : null;
  }

  getIdentitySignatureChain(): Uint8Array[] {
    return this.identitySignatureChain;
  }

  getRelayerAddress(): string | null {
    return this.relayer ? computeAddress(this.relayer.publicKey) : null;
  }

  /** Uncompressed secp256k1 relayer public key, 65 bytes. */
  getRelayerPublicKey(): Uint8Array | null {
    return this.relayer ? getBytes(this.relayer.publicKey) : null;
  }

  getRelayerSignatureChain(): Uint8Array[] {
    return this.relayerSignatureChain;
  }

  /**
   * Signs a transaction from the relayer wallet. Only RelayerService calls
   * this, for transactions it builds itself: no endpoint reaches it.
   * @returns The serialized signed transaction
   */
  signRelayerTransaction(request: TransactionLike<string>): string {
    if (!this.relayer) {
      throw new Error('Relayer key not derived');
    }
    const tx = Transaction.from(request);
    tx.signature = this.relayer.sign(tx.unsignedHash);
    return tx.serialized;
  }

  /** The key manifest signed at boot, for this CVM's app id. */
  getKeyManifest(): SignedKeyManifest | null {
    return this.keyManifest;
  }

  /**
   * Signs the EIP-712 key manifest binding Wulong's public keys to its app id.
   */
  signKeyManifest(appId: string, epoch = 1): SignedKeyManifest {
    if (!this.identity || !this.mlkemPublicKey || !this.relayer) {
      throw new Error('Keys not derived');
    }
    const manifest: KeyManifest = {
      appId,
      mlkemPublicKeyHash: sha256(this.mlkemPublicKey),
      relayer: computeAddress(this.relayer.publicKey),
      epoch,
    };
    const digest = TypedDataEncoder.hash(
      KEY_MANIFEST_DOMAIN,
      KEY_MANIFEST_TYPES,
      manifest,
    );
    return { manifest, signature: this.identity.sign(digest).serialized };
  }
}

function lengthPrefixed(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf-8');
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(bytes.length);
  return Buffer.concat([prefix, bytes]);
}
