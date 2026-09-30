import {
  Interface,
  Provider,
  Signature,
  SigningKey,
  computeAddress,
  concat,
  getBytes,
  hexlify,
  keccak256,
  toUtf8Bytes,
} from 'ethers';

const KEY_CLAIM_TAG = 'dstack-guest-v1-key-claim';
const KMS_ISSUED_PREFIX = 'dstack-kms-issued:';
// secp256k1 order / 2: signatures with a larger s are malleable copies
const HALF_ORDER =
  0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;

const DSTACK_KMS = new Interface([
  'function kmsInfo() view returns (bytes k256Pubkey, bytes caPubkey, bytes quote, bytes eventlog)',
]);

export interface KeyChainInput {
  /** The derived public key, any SEC1 encoding (uncompressed or compressed). */
  publicKey: Uint8Array;
  domain: string;
  algorithm: 'secp256k1' | 'ed25519';
  /** The two links returned by GetKey. */
  signatureChain: Uint8Array[];
  /** The app id the key must belong to. */
  appId: string;
  /** The KMS root public key, from DstackKms.kmsInfo() on chain. */
  kmsRootPublicKey: Uint8Array;
}

/**
 * The v1 key claim signed by the app root key (link 0), per
 * https://github.com/Dstack-TEE/dstack/blob/master/docs/guest-api-v1.md#link-0-the-key-claim
 */
export function keyClaim(
  algorithm: string,
  domain: string,
  publicKey: Uint8Array,
): Uint8Array {
  return getBytes(
    concat([
      lengthPrefixed(toUtf8Bytes(KEY_CLAIM_TAG)),
      lengthPrefixed(toUtf8Bytes(algorithm)),
      lengthPrefixed(toUtf8Bytes(domain)),
      lengthPrefixed(publicKey),
    ]),
  );
}

/**
 * Verifies a GetKey v1 signature chain up to the KMS root, as described in
 * docs/KEY_DERIVATION.md#verification step 3. Only secp256k1 keys are
 * checked here: they are the only keys Wulong serves a chain for.
 * @returns The failed checks, empty when the chain holds
 */
export function verifyKeyChain(input: KeyChainInput): string[] {
  if (input.algorithm !== 'secp256k1') {
    return [`Only secp256k1 chains are verified, not ${input.algorithm}`];
  }
  if (input.signatureChain.length !== 2) {
    return ['The signature chain must have two links'];
  }

  let publicKey: string;
  let appRoot: string;
  try {
    publicKey = SigningKey.computePublicKey(input.publicKey, true);
    const digest0 = keccak256(
      keyClaim(input.algorithm, input.domain, getBytes(publicKey)),
    );
    appRoot = recover(digest0, input.signatureChain[0]);
  } catch (error) {
    return [`Link 0 is invalid: ${(error as Error).message}`];
  }

  try {
    const digest1 = keccak256(
      concat([toUtf8Bytes(KMS_ISSUED_PREFIX), input.appId, appRoot]),
    );
    const kmsRoot = recover(digest1, input.signatureChain[1]);
    if (
      computeAddress(kmsRoot) !==
      computeAddress(SigningKey.computePublicKey(input.kmsRootPublicKey, true))
    ) {
      return ['Link 1 is not signed by the KMS root'];
    }
  } catch (error) {
    return [`Link 1 is invalid: ${(error as Error).message}`];
  }
  return [];
}

/** Reads the KMS root public key from the DstackKms contract. */
export async function readKmsRootPublicKey(
  provider: Pick<Provider, 'call'>,
  kms: string,
): Promise<Uint8Array> {
  const result = await provider.call({
    to: kms,
    data: DSTACK_KMS.encodeFunctionData('kmsInfo'),
  });
  const [k256Pubkey] = DSTACK_KMS.decodeFunctionResult('kmsInfo', result);
  return getBytes(k256Pubkey as string);
}

/** Recovers the compressed signer of a 65-byte `r || s || v` link. */
function recover(digest: string, link: Uint8Array): string {
  if (link.length !== 65) {
    throw new Error('a link must be 65 bytes');
  }
  const s = BigInt(`0x${Buffer.from(link.subarray(32, 64)).toString('hex')}`);
  if (s > HALF_ORDER) {
    throw new Error('high-S signature');
  }
  const v = link[64];
  if (v > 1 && v !== 27 && v !== 28) {
    throw new Error(`unsupported recovery id ${v}`);
  }
  const signature = Signature.from({
    r: hexlify(link.subarray(0, 32)),
    s: hexlify(link.subarray(32, 64)),
    v: v < 27 ? 27 + v : v,
  });
  return SigningKey.computePublicKey(
    SigningKey.recoverPublicKey(digest, signature),
    true,
  );
}

function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, bytes.length);
  return getBytes(concat([prefix, bytes]));
}
