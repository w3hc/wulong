import { SigningKey, concat, getBytes, keccak256, toUtf8Bytes } from 'ethers';
import { keyClaim, readKmsRootPublicKey, verifyKeyChain } from './key-chain';

// App root key and link 0 vector from the dstack guest API v1 spec
const appRoot = new SigningKey(
  '0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
);
const derived = new SigningKey(
  '0x5510330f86902ddae38c6d89c93a8408019332c17a429e1abd01c4a28d1544a6',
);
const LINK0 =
  '5b6193729ce7976ec67863f21692d4b98c69832698aae8e001a7d33a6f818b6e' +
  '46ca950725b6e90e8ca9bcf394abd03ce264bf9b7eec1e91693247f9dd53c269' +
  '01';

const kmsRoot = new SigningKey('0x' + '5a'.repeat(32));
const appId = '0x1111111111111111111111111111111111111111';

const link = (key: SigningKey, digest: string) => {
  const { r, s, yParity } = key.sign(digest);
  return getBytes(concat([r, s, new Uint8Array([yParity])]));
};

const chain = (id = appId, kms = kmsRoot) => {
  const link0 = link(
    appRoot,
    keccak256(
      keyClaim(
        'secp256k1',
        'storage-encryption',
        getBytes(derived.compressedPublicKey),
      ),
    ),
  );
  const link1 = link(
    kms,
    keccak256(
      concat([
        toUtf8Bytes('dstack-kms-issued:'),
        id,
        appRoot.compressedPublicKey,
      ]),
    ),
  );
  return [link0, link1];
};

const input = (overrides = {}) => ({
  publicKey: getBytes(derived.publicKey),
  domain: 'storage-encryption',
  algorithm: 'secp256k1' as const,
  signatureChain: chain(),
  appId,
  kmsRootPublicKey: getBytes(kmsRoot.publicKey),
  ...overrides,
});

describe('verifyKeyChain', () => {
  it('builds link 0 exactly as the spec vector', () => {
    expect(Buffer.from(chain()[0]).toString('hex')).toBe(LINK0);
  });

  it('accepts a chain from the KMS root, with an uncompressed key', () => {
    expect(verifyKeyChain(input())).toEqual([]);
  });

  it('accepts a compressed public key', () => {
    expect(
      verifyKeyChain(
        input({ publicKey: getBytes(derived.compressedPublicKey) }),
      ),
    ).toEqual([]);
  });

  it('rejects a key claimed under another domain', () => {
    expect(verifyKeyChain(input({ domain: 'wulong/relayer/evm/v1' }))).toEqual([
      'Link 1 is not signed by the KMS root',
    ]);
  });

  it('rejects another app id', () => {
    expect(verifyKeyChain(input({ appId: '0x' + '22'.repeat(20) }))).toEqual([
      'Link 1 is not signed by the KMS root',
    ]);
  });

  it('rejects a chain issued by another KMS', () => {
    expect(
      verifyKeyChain(
        input({
          signatureChain: chain(appId, new SigningKey('0x' + '5b'.repeat(32))),
        }),
      ),
    ).toEqual(['Link 1 is not signed by the KMS root']);
  });

  it('rejects a high-S link', () => {
    const [link0, link1] = chain();
    const n =
      0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const s = BigInt(
      `0x${Buffer.from(link0.subarray(32, 64)).toString('hex')}`,
    );
    const malleable = new Uint8Array(link0);
    malleable.set(
      Buffer.from((n - s).toString(16).padStart(64, '0'), 'hex'),
      32,
    );
    malleable[64] ^= 1;

    expect(
      verifyKeyChain(input({ signatureChain: [malleable, link1] })),
    ).toEqual(['Link 0 is invalid: high-S signature']);
  });

  it('rejects a chain without two links', () => {
    expect(verifyKeyChain(input({ signatureChain: [] }))).toEqual([
      'The signature chain must have two links',
    ]);
  });
});

describe('readKmsRootPublicKey', () => {
  it('reads k256Pubkey from DstackKms.kmsInfo()', async () => {
    const { AbiCoder } = await import('ethers');
    const pubkey = kmsRoot.compressedPublicKey;
    const call = jest.fn(() =>
      Promise.resolve(
        AbiCoder.defaultAbiCoder().encode(
          ['bytes', 'bytes', 'bytes', 'bytes'],
          [pubkey, '0x', '0x', '0x'],
        ),
      ),
    );

    const result = await readKmsRootPublicKey({ call }, '0x' + '33'.repeat(20));

    expect(Buffer.from(result).toString('hex')).toBe(pubkey.slice(2));
  });
});
