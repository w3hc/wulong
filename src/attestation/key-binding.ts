import { createHash } from 'crypto';
import { computeAddress, getAddress, verifyTypedData } from 'ethers';
import {
  KEY_MANIFEST_DOMAIN,
  KEY_MANIFEST_TYPES,
  SignedKeyManifest,
} from '../keys/key-derivation.service';
import { buildReportData } from './report-data';

/** Offset of REPORTDATA in a TDX v4 quote: 48-byte header + 520 into the body. */
export const TDX_QUOTE_REPORT_DATA_OFFSET = 568;

/** The fields of `GET /chest/attestation` that bind the keys. */
export interface KeyBindingEvidence {
  mlkemPublicKey: string;
  identityPublicKey: string;
  reportData: string;
  keyManifest: SignedKeyManifest;
  /** Base64 DER of the TLS leaf certificate served from inside the enclave. */
  tlsCertificate?: string;
}

/**
 * Checks that an attestation commits to the keys it returns, as described in
 * docs/KEY_DERIVATION.md#verification. It does not verify the quote itself,
 * the measurements or the GetKey signature chain.
 * @param evidence The attestation response
 * @param options.nonce The nonce the client sent, if any
 * @param options.quote The raw TDX quote, to check its report_data
 * @param options.servedCertificate DER of the certificate the TLS session
 * presented, to check TLS terminates inside the enclave
 * @returns The failed checks, empty when the binding holds
 */
export function verifyKeyBinding(
  evidence: KeyBindingEvidence,
  options: { nonce?: Buffer; quote?: Buffer; servedCertificate?: Buffer } = {},
): string[] {
  const failures: string[] = [];
  const ek = Buffer.from(evidence.mlkemPublicKey, 'base64');
  const identity = Buffer.from(strip0x(evidence.identityPublicKey), 'hex');
  const reportData = Buffer.from(strip0x(evidence.reportData), 'hex');
  const tlsCertificate = evidence.tlsCertificate
    ? Buffer.from(evidence.tlsCertificate, 'base64')
    : undefined;

  const expected = buildReportData(
    {
      mlkemPublicKey: ek,
      identityPublicKey: identity,
      tlsCertificateDer: tlsCertificate,
    },
    options.nonce,
  );
  if (!reportData.equals(expected)) {
    failures.push('reportData does not commit to the returned keys and nonce');
  }

  if (options.servedCertificate) {
    if (!tlsCertificate) {
      failures.push(
        'The attestation binds no TLS certificate: TLS terminates outside the enclave',
      );
    } else if (!options.servedCertificate.equals(tlsCertificate)) {
      failures.push(
        'The TLS session certificate is not the one bound by the attestation',
      );
    }
  }

  if (options.quote) {
    const quoted = options.quote.subarray(
      TDX_QUOTE_REPORT_DATA_OFFSET,
      TDX_QUOTE_REPORT_DATA_OFFSET + 64,
    );
    if (!quoted.equals(expected)) {
      failures.push('The quote report_data does not match');
    }
  }

  const { manifest, signature } = evidence.keyManifest;
  const mlkemPublicKeyHash = `0x${createHash('sha256').update(ek).digest('hex')}`;
  if (manifest.mlkemPublicKeyHash.toLowerCase() !== mlkemPublicKeyHash) {
    failures.push('The key manifest commits to a different ML-KEM key');
  }
  try {
    const signer = verifyTypedData(
      KEY_MANIFEST_DOMAIN,
      KEY_MANIFEST_TYPES,
      manifest,
      signature,
    );
    if (
      getAddress(signer) !== computeAddress(`0x${identity.toString('hex')}`)
    ) {
      failures.push('The key manifest is not signed by the identity key');
    }
  } catch {
    failures.push('The key manifest signature is invalid');
  }

  return failures;
}

function strip0x(value: string): string {
  return value.startsWith('0x') ? value.slice(2) : value;
}
