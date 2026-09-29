import { createHash } from 'crypto';
import {
  SigningKey,
  TypedDataEncoder,
  Wallet,
  ZeroAddress,
  getBytes,
} from 'ethers';
import {
  KEY_MANIFEST_DOMAIN,
  KEY_MANIFEST_TYPES,
  KeyManifest,
} from '../keys/key-derivation.service';
import {
  KeyBindingEvidence,
  TDX_QUOTE_REPORT_DATA_OFFSET,
  verifyKeyBinding,
} from './key-binding';
import { buildReportData } from './report-data';

const identity = new SigningKey('0x' + '42'.repeat(32));
const ek = Buffer.alloc(1568, 0x01);
const nonce = Buffer.alloc(32, 0x7f);

const sign = (manifest: KeyManifest, key = identity) =>
  key.sign(
    TypedDataEncoder.hash(KEY_MANIFEST_DOMAIN, KEY_MANIFEST_TYPES, manifest),
  ).serialized;

const evidence = (overrides: Partial<KeyBindingEvidence> = {}) => {
  const manifest: KeyManifest = {
    appId: '0x1111111111111111111111111111111111111111',
    mlkemPublicKeyHash: `0x${createHash('sha256').update(ek).digest('hex')}`,
    relayer: ZeroAddress,
    epoch: 1,
  };
  const reportData = buildReportData(
    { mlkemPublicKey: ek, identityPublicKey: getBytes(identity.publicKey) },
    nonce,
  );
  return {
    mlkemPublicKey: ek.toString('base64'),
    identityPublicKey: identity.publicKey,
    reportData: `0x${reportData.toString('hex')}`,
    keyManifest: { manifest, signature: sign(manifest) },
    ...overrides,
  };
};

const quoteWith = (reportData: string) => {
  const quote = Buffer.alloc(1024);
  Buffer.from(reportData.slice(2), 'hex').copy(
    quote,
    TDX_QUOTE_REPORT_DATA_OFFSET,
  );
  return quote;
};

describe('verifyKeyBinding', () => {
  it('accepts an attestation that binds its keys, nonce and quote', () => {
    const valid = evidence();

    expect(
      verifyKeyBinding(valid, { nonce, quote: quoteWith(valid.reportData) }),
    ).toEqual([]);
  });

  it('rejects a swapped ML-KEM key', () => {
    const swapped = evidence({
      mlkemPublicKey: Buffer.alloc(1568, 0x02).toString('base64'),
    });

    expect(verifyKeyBinding(swapped, { nonce })).toEqual([
      'reportData does not commit to the returned keys and nonce',
      'The key manifest commits to a different ML-KEM key',
    ]);
  });

  it('rejects a replayed attestation for another nonce', () => {
    expect(
      verifyKeyBinding(evidence(), { nonce: Buffer.alloc(32, 0x01) }),
    ).toEqual(['reportData does not commit to the returned keys and nonce']);
  });

  it('rejects a quote whose report_data differs', () => {
    const valid = evidence();

    expect(
      verifyKeyBinding(valid, { nonce, quote: Buffer.alloc(1024) }),
    ).toEqual(['The quote report_data does not match']);
  });

  it('rejects a manifest signed by another key', () => {
    const valid = evidence();
    const other = new SigningKey(Wallet.createRandom().privateKey);
    const keyManifest = {
      manifest: valid.keyManifest.manifest,
      signature: sign(valid.keyManifest.manifest, other),
    };

    expect(verifyKeyBinding({ ...valid, keyManifest }, { nonce })).toEqual([
      'The key manifest is not signed by the identity key',
    ]);
  });
});
