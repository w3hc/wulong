import { createHash, hkdfSync } from 'crypto';
import { SigningKey, getBytes, verifyTypedData } from 'ethers';
import { createMlKem1024 } from 'mlkem';
import {
  DstackV1Client,
  GetKeyResponse,
  KeyAlgorithm,
} from './dstack-v1.client';
import {
  KEY_MANIFEST_DOMAIN,
  KEY_MANIFEST_TYPES,
  KeyDerivationService,
} from './key-derivation.service';

// App root key from the dstack guest API v1 spec test vectors
const ROOT_KEY =
  '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b';

const lp = (value: string) => {
  const bytes = Buffer.from(value, 'utf-8');
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(bytes.length);
  return Buffer.concat([prefix, bytes]);
};

/** In-process dstack agent implementing the v1 KDF (guest-api-v1.md). */
class FakeDstack {
  simulator = false;
  failing = false;

  isSimulator() {
    return this.simulator;
  }

  getKey(domain: string, algorithm: KeyAlgorithm): Promise<GetKeyResponse> {
    if (this.failing) {
      return Promise.reject(new Error('connect ENOENT /var/run/dstack.sock'));
    }
    const info = Buffer.concat([
      lp('dstack-guest-v1-key'),
      lp(algorithm),
      lp(domain),
    ]);
    const key = new Uint8Array(
      hkdfSync(
        'sha256',
        Buffer.from(ROOT_KEY, 'hex'),
        'dstack-guest-v1',
        info,
        32,
      ),
    );
    const publicKey =
      algorithm === 'secp256k1'
        ? getBytes(SigningKey.computePublicKey(key, true))
        : new Uint8Array(0);
    return Promise.resolve({ key, publicKey, signatureChain: [] });
  }
}

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
const sha256 = (bytes: Uint8Array) =>
  createHash('sha256').update(bytes).digest('hex');

describe('KeyDerivationService', () => {
  let dstack: FakeDstack;
  const originalEnv = process.env.NODE_ENV;

  const create = async () => {
    const service = new KeyDerivationService(
      dstack as unknown as DstackV1Client,
    );
    await service.onModuleInit();
    return service;
  };

  beforeEach(() => {
    dstack = new FakeDstack();
  });

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  describe('test vectors', () => {
    it('fake agent matches the dstack v1 KDF vectors', async () => {
      const secp = await dstack.getKey('storage-encryption', 'secp256k1');
      const ed = await dstack.getKey('storage-encryption', 'ed25519');
      const abc = await dstack.getKey('a/b/c', 'secp256k1');

      expect(hex(secp.key)).toBe(
        '5510330f86902ddae38c6d89c93a8408019332c17a429e1abd01c4a28d1544a6',
      );
      expect(hex(secp.publicKey)).toBe(
        '03d962450a41748021c8b02787ac36ce642ff0ae25f4c55019eb527e1112cfd764',
      );
      expect(hex(ed.key)).toBe(
        '3c4c3ece12fa99ccb93fc0090877f80e70545fdd971e2ac93d3398c4684538d3',
      );
      expect(hex(abc.key)).toBe(
        '7f0973449298085d2d36a3b4c4d3243c100ba1981ffa885fe9e9dee883e69538',
      );
    });

    it('mlkem deriveKeyPair matches NIST ACVP ML-KEM-1024 keyGen (tgId 3, tcId 51)', async () => {
      const d =
        'F3A706FAF090C03DB506863AB0B20BD8A1627956318E88C67EB875E8E7266009';
      const z =
        '35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275';
      const mlkem = await createMlKem1024();

      const [ek, dk] = mlkem.deriveKeyPair(
        new Uint8Array(Buffer.from(d + z, 'hex')),
      );

      expect(sha256(ek)).toBe(
        'b78619e4fceeeb86dee3fedb945eca6da61dae312771ef8fa871951d391bd7b6',
      );
      expect(sha256(dk)).toBe(
        '925ed6f1cf0379ede29d8209432d6e08c73ed0423883febf85416343f4fa1f86',
      );
    });

    it('derives the pinned keys from the spec root key', async () => {
      // Changing these means every stored secret becomes undecryptable
      const service = await create();

      expect(sha256(service.getMlKemPublicKey()!)).toBe(
        'f148afce91b735e41b2633a363c331ea128aa52d3015be0e2af2deb2c896e859',
      );
      expect(service.getIdentityAddress()).toBe(
        '0xBd6E221AB7C3E8eD8c2DEdeaF7B1132653d6587F',
      );
    });
  });

  describe('derivation', () => {
    it('is deterministic across instances', async () => {
      const a = await create();
      const b = await create();

      expect(hex(a.getMlKemPublicKey()!)).toBe(hex(b.getMlKemPublicKey()!));
      expect(a.getIdentityAddress()).toBe(b.getIdentityAddress());
    });

    it('decapsulates what is encapsulated to its public key', async () => {
      const service = await create();
      const mlkem = await createMlKem1024();

      const [ciphertext, sharedSecret] = mlkem.encap(
        service.getMlKemPublicKey()!,
      );

      expect(hex(service.decapsulate(ciphertext))).toBe(hex(sharedSecret));
    });

    it('signs a key manifest recoverable to the identity address', async () => {
      const service = await create();
      const appId = '0x' + '11'.repeat(20);

      const { manifest, signature } = service.signKeyManifest(appId);

      expect(manifest.mlkemPublicKeyHash).toBe(
        '0x' + sha256(service.getMlKemPublicKey()!),
      );
      expect(
        verifyTypedData(
          KEY_MANIFEST_DOMAIN,
          KEY_MANIFEST_TYPES,
          manifest,
          signature,
        ),
      ).toBe(service.getIdentityAddress());
    });
  });

  describe('failure modes', () => {
    it('refuses the simulator in production', async () => {
      process.env.NODE_ENV = 'production';
      dstack.simulator = true;

      await expect(create()).rejects.toThrow('DSTACK_SIMULATOR_ENDPOINT');
    });

    it('fails startup in production when dstack is unreachable', async () => {
      process.env.NODE_ENV = 'production';
      dstack.failing = true;

      await expect(create()).rejects.toThrow('Key derivation');
    });

    it('starts without keys outside production when dstack is unreachable', async () => {
      process.env.NODE_ENV = 'development';
      dstack.failing = true;

      const service = await create();

      expect(service.isAvailable()).toBe(false);
      expect(service.getMlKemPublicKey()).toBeNull();
      expect(() => service.decapsulate(new Uint8Array(1568))).toThrow(
        'not derived',
      );
    });
  });
});
