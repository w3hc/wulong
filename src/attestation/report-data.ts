import { createHash } from 'crypto';

export const REPORT_DATA_LABEL = 'wulong-report-v1';
export const NONCE_LENGTH = 32;

/**
 * Public values committed to by the quote. A key or certificate that does not
 * exist yet contributes an empty term.
 */
export interface ReportDataInputs {
  /** ML-KEM-1024 encapsulation key `ek`. */
  mlkemPublicKey: Uint8Array;
  /** Relayer address, 20 bytes. */
  relayer?: Uint8Array;
  /** Uncompressed secp256k1 identity public key, 65 bytes. */
  identityPublicKey?: Uint8Array;
  /** DER of the TLS leaf certificate served from inside the enclave. */
  tlsCertificateDer?: Uint8Array;
}

/**
 * Builds the 64-byte TDX `report_data`:
 *
 *   [0..32]  SHA-256(LP(label) || LP(ek) || LP(relayer) || LP(identity_pubkey)
 *                    || LP(SHA-256(tls_leaf_cert_der)))
 *   [32..64] client nonce, or zeros
 *
 * See docs/KEY_DERIVATION.md#report_data.
 */
export function buildReportData(
  inputs: ReportDataInputs,
  nonce?: Uint8Array,
): Buffer {
  if (nonce && nonce.length !== NONCE_LENGTH) {
    throw new Error(`Nonce must be ${NONCE_LENGTH} bytes`);
  }
  const empty = new Uint8Array(0);
  const certificateHash = inputs.tlsCertificateDer
    ? createHash('sha256').update(inputs.tlsCertificateDer).digest()
    : empty;
  const commitment = createHash('sha256')
    .update(lengthPrefixed(Buffer.from(REPORT_DATA_LABEL, 'utf-8')))
    .update(lengthPrefixed(inputs.mlkemPublicKey))
    .update(lengthPrefixed(inputs.relayer ?? empty))
    .update(lengthPrefixed(inputs.identityPublicKey ?? empty))
    .update(lengthPrefixed(certificateHash))
    .digest();
  return Buffer.concat([
    commitment,
    nonce ? Buffer.from(nonce) : Buffer.alloc(NONCE_LENGTH),
  ]);
}

/**
 * Parses a client nonce given as 64 hex characters, with or without `0x`.
 * Returns undefined when no nonce was sent.
 */
export function parseNonce(value?: string): Buffer | undefined {
  if (value === undefined || value === '') {
    return undefined;
  }
  const hex = value.startsWith('0x') ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`Nonce must be ${NONCE_LENGTH} bytes of hex`);
  }
  return Buffer.from(hex, 'hex');
}

function lengthPrefixed(bytes: Uint8Array): Buffer {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(bytes.length);
  return Buffer.concat([prefix, bytes]);
}
