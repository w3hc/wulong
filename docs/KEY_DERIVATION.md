# Enclave-Derived Keys

Design for how Wulong obtains its long-lived private keys so that they exist only inside the attested enclave, and no one, the operator included, can obtain them. Tracks [#31](https://github.com/w3hc/wulong/issues/31). **Status:** ML-KEM and identity key derivation are implemented ([#33](https://github.com/w3hc/wulong/issues/33)), and `GET /chest/attestation` serves the key manifest and the new `report_data` ([#35](https://github.com/w3hc/wulong/issues/35)), and TLS terminates inside the enclave with its leaf certificate bound into `report_data` ([#37](https://github.com/w3hc/wulong/issues/37)); the relayer wallet and on-chain governance are not yet.

## Table of Contents

- [Summary](#summary)
- [Why not the current setup, or zk-api's](#why-not-the-current-setup-or-zk-apis)
- [Derivation](#derivation)
- [Binding the public keys](#binding-the-public-keys)
- [Verification](#verification)
- [What "no one can know" rests on](#what-no-one-can-know-rests-on)
- [Upgrade governance](#upgrade-governance)
- [The relayer wallet](#the-relayer-wallet)
- [Rotation](#rotation)
- [Development mode](#development-mode)
- [Implementation outline](#implementation-outline)
- [Open questions](#open-questions)
- [Sources](#sources)

## Summary

Wulong holds three keys, all derived at boot from the [dstack](https://github.com/Dstack-TEE/dstack) KMS with the v1 guest API `GetKey`, and never stored, exported or passed through env:

| Key | `GetKey` domain | Algorithm | Used for |
| --- | --- | --- | --- |
| ML-KEM-1024 decapsulation key | `wulong/mlkem-1024/v1` | `ed25519` (used as a 32-byte seed) | Decrypting the server recipient entry of stored secrets |
| Relayer wallet | `wulong/relayer/evm/v1` | `secp256k1` | Sending transactions for future on-chain actions |
| Identity key | `wulong/identity/v1` | `secp256k1` | Signing the key manifest that binds the other public keys |

`GetKey` is deterministic in `(app_id, domain, algorithm)`: every instance of the app, on every restart, gets the same keys, so nothing needs to be persisted or backed up. The KMS releases the app's root key only to a CVM whose boot measurements match the app's on-chain policy (allowed compose hash, allowed OS image), so only code the app owner has registered on chain can ever derive them.

The proof has three independent parts:

1. **Attestation**: a TDX quote whose `report_data` commits to the public keys shows they are held by the measured code on genuine hardware.
2. **Signature chain**: the chain returned by `GetKey` shows the keys are the app's deterministic keys under a known KMS root, anchored in the `DstackKms` contract. The relayer address is also verifiable on chain.
3. **Governance**: the app's `DstackApp` contract shows which code versions have ever been allowed to derive the keys, and who can add more.

## Why not the current setup, or zk-api's

**Current Wulong.** The key pair is generated off-box by [`scripts/generate-admin-keypair.ts`](../scripts/generate-admin-keypair.ts) and passed as `ADMIN_MLKEM_PRIVATE_KEY` in env. Whoever ran the script, and anyone who can read the deployment env, has the key.

**zk-api's `TeeKeyManagerService`.** It generates the key pair inside the TEE, which is the right instinct, but:

- The "sealing" key is `SHA-256("<TEE_PLATFORM>:<TEE_MEASUREMENT>")`, both read from env, and defaulting to `development-only-key`. Anyone who knows those two strings can unseal `/sealed-storage/mlkem-private.key`. It is not bound to any hardware or KMS secret.
- The key is random, so it lives only in that file. Losing the volume loses every stored secret, and a second instance has a different key.
- Nothing proves to a third party that the file was never copied out before sealing.

**KMS-held secrets released on attestation** (the `loadFromKms` path of the former `SecretsService`, removed in [#44](https://github.com/w3hc/wulong/issues/44)). A key someone generated and uploaded to a KMS was known to that someone. Derivation avoids that: the key is a function of a root that is itself generated inside a TEE, and nobody ever handles it.

## Derivation

All three keys use the dstack **v1** guest API (`POST /v1/GetKey` on `/var/run/dstack.sock`, dstack ≥ 0.6.0), specified in [guest-api-v1.md](https://github.com/Dstack-TEE/dstack/blob/master/docs/guest-api-v1.md#key-derivation):

```text
key = HKDF-SHA256(
  salt = "dstack-guest-v1",
  IKM  = app root secp256k1 key (released by the KMS to this app only),
  info = LP("dstack-guest-v1-key") || LP(algorithm) || LP(domain),
  L    = 32)
```

where `LP(x) = uint32_be(len(x)) || x`. v1 is preferred over the v0 `getKey(path)` that `@phala/dstack-sdk` 0.5.x exposes because v0 ignores the algorithm, so the same 32 bytes would serve both curves, and because its signature-chain claim can be steered by the caller. No Wulong key has been derived yet, so starting on v1 costs nothing, while switching later is a key rotation.

### ML-KEM-1024

ML-KEM key generation takes a 64-byte seed `d || z` ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), `ML-KEM.KeyGen_internal`). `GetKey` returns 32 bytes, so the seed is expanded with a Wulong-specific label:

```text
s        = GetKey("wulong/mlkem-1024/v1", "ed25519").key          # 32 bytes
seed     = HKDF-SHA256(salt = "wulong", IKM = s,
                       info = LP("wulong-mlkem-1024-seed-v1"), L = 64)
(ek, dk) = mlkem.deriveKeyPair(seed)                               # d = seed[0..32], z = seed[32..64]
```

`ed25519` is requested only because its 32 bytes are used as an opaque seed, with no range check. The ed25519 key itself is never used. The [`mlkem`](https://github.com/dajiaji/crystals-kyber-js) package Wulong already uses supports `deriveKeyPair(seed)`, and keeping the 64-byte seed as the root is also what [draft-connolly-cfrg-hpke-mlkem](https://www.ietf.org/archive/id/draft-connolly-cfrg-hpke-mlkem-04.html) recommends.

### Relayer and identity keys

```text
relayer  = GetKey("wulong/relayer/evm/v1", "secp256k1").key        # private scalar, in range by construction
identity = GetKey("wulong/identity/v1",    "secp256k1").key
```

v1 guarantees the 32 bytes are a valid secp256k1 scalar (it fails rather than folding an out-of-range value), so they are used directly as Ethereum private keys (`new ethers.Wallet(hex)`). Do not use the SDK's `toViemAccountSecure`: it is a v0-only adapter.

The identity key is kept separate from the relayer so that the key that holds funds never signs statements about Wulong, and the key that signs statements never holds funds.

## Binding the public keys

### Key manifest

At boot, the identity key signs an [EIP-712](https://eips.ethereum.org/EIPS/eip-712) manifest:

```solidity
// domain: { name: "Wulong", version: "1" }
struct KeyManifest {
    address appId;              // the DstackApp contract address
    bytes32 mlkemPublicKeyHash; // SHA-256(ek)
    address relayer;
    uint64  epoch;              // key generation, see Rotation
}
```

`GET /chest/attestation` returns the manifest, its signature, the full ML-KEM public key, and the `GetKey` signature chains of the identity and relayer keys.

### `report_data`

The TDX quote's 64-byte `report_data` becomes:

```text
report_data[0..32]  = SHA-256( LP("wulong-report-v1") || LP(ek) || LP(relayer)
                               || LP(identity_pubkey) || LP(SHA-256(tls_leaf_cert_der)) )
report_data[32..64] = client nonce (32 bytes), or zeros if none was sent
```

This supersedes the `SHA-256(pk) || SHA-256(cert)` layout used by zk-api: one hash commits to every key, and the second half carries a client challenge for freshness. The TLS certificate is the leaf of the chain the dstack KMS issues to the app (`GetTlsKey`), whose private key is generated inside the CVM and never leaves it. A client checks that the certificate of its TLS session is the one committed to here, which proves the session ends inside the enclave rather than at a proxy. The term is empty only under the `ALLOW_TLS_OUTSIDE_ENCLAVE` opt-out, where clients must refuse to send secrets.

## Verification

A client, before encrypting to Wulong, or an auditor, at any time:

1. **Quote.** Verify the attestation from `GET /chest/attestation?nonce=<32 bytes>` with dstack's verifier (or `@phala/dcap-qvl`): valid Intel signature, TCB up to date, `report_data` equal to the recomputation above with the client's nonce.
2. **Code.** Replay the event log into RTMR3 and read the `compose_hash`, `app_id` and `os_image_hash`. Check that `compose_hash` belongs to a published Wulong release whose image digest is reproducible from source, and that `app_id` is Wulong's known `DstackApp` address. Never trust an `app_id` read from the CVM's own `Info`.
3. **Chain.** For the identity and relayer keys, verify each `GetKey` signature chain per the [v1 spec](https://github.com/Dstack-TEE/dstack/blob/master/docs/guest-api-v1.md#verifying-a-chain), anchored on `DstackKms.kmsInfo().k256Pubkey` read from the chain, not from Wulong.
4. **Manifest.** Recover the manifest signer and check that it is the identity key from step 3, that `appId` matches, and that `mlkemPublicKeyHash` is `SHA-256(ek)`.
5. **Governance.** Read the `DstackApp` contract: owner, allowed compose hashes (current and past `ComposeHashAdded` events), upgrade status. See [Upgrade governance](#upgrade-governance).

Steps 1–2 prove the keys are held by that code now. Steps 3–4 prove they are the app's stable keys under the KMS, so a client can pin `ek` and the relayer address once and re-check only the chain. Step 5 tells the client which code can ever hold them.

**On chain.** Link 1 of the chain is `keccak256("dstack-kms-issued:" || app_id || app_root_pubkey)` and link 0 is a keccak digest of a length-prefixed claim, both signed as recoverable secp256k1 signatures. A contract can therefore verify, with `ecrecover` and the KMS root address as an immutable, that an address is Wulong's relayer (or that a manifest came from Wulong's identity key) without any off-chain oracle. The caller passes the uncompressed public keys so the contract can rebuild the compressed form and check them against the recovered addresses.

## What "no one can know" rests on

With this design, learning a Wulong private key requires one of the following. There is no key to leak from env, disk or a backup.

| Assumption | Who could break it | Mitigation |
| --- | --- | --- |
| Every compose hash ever allowed on the `DstackApp` never exports the keys | The `DstackApp` owner, by registering a build that does | Multisig + timelock owner, removal of superseded hashes, reproducible builds; see below |
| Nothing else in the CVM can reach `/var/run/dstack.sock` | The operator, via an extra container or SSH | The compose file has one service; production OS image only (no SSH), checked through `os_image_hash` |
| Every OS image allowed by `DstackKms` is honest | The `DstackKms` owner (Phala for Phala's KMS) | Pin accepted `os_image_hash` values client-side; self-host a KMS if this is unacceptable |
| The `DstackKms` implementation is not upgraded to bypass `isAppAllowed` | The `DstackKms` owner (the contract is UUPS-upgradeable) | Watch `Upgraded` events; same as above |
| The KMS root key stays secret | KMS nodes are TDX CVMs that generate the root inside and replicate it over RA-TLS to attested peers | Trust in TDX and the measured KMS code. The root cannot be rotated today ([dstack#1287](https://github.com/Dstack-TEE/dstack/issues/1287)), so a root compromise exposes every key it ever derived |
| TDX keeps CVM memory confidential | Intel, or a hardware or side-channel attack | TCB up-to-date requirement; see [SIDE_CHANNEL_ATTACKS.md](./SIDE_CHANNEL_ATTACKS.md) |

The operator (the person running the Phala deployment) holds none of these levers unless they also own the `DstackApp` contract. The claim to users is therefore precise: **the keys can only be known by code that was publicly registered on chain, under the governance rules readable on chain, on hardware and a KMS whose integrity is attested.** It is not "no one, unconditionally".

Phala Cloud's default (off-chain) KMS does not give this property: its app allowlist is not publicly governed. Wulong must be deployed against the **on-chain KMS** (`DstackKms` on Base), where the app id is the `DstackApp` contract address.

## Upgrade governance

The `DstackApp` owner can call `addComposeHash`, so the owner is the real key holder: they can ship a build that prints the keys. This is made visible and slow rather than impossible:

- **Owner**: a [Safe](https://safe.global/) multisig behind an OpenZeppelin `TimelockController` (for example a 7-day delay). An upgrade is public on chain from the moment it is scheduled, and users can review it and withdraw their secrets before it can boot.
- **Release discipline**: each allowed compose hash pins the image by digest, not a mutable tag, is published with its source commit, and has a reproducible build.
- **Retire old versions**: `removeComposeHash` the previous version in the same timelock batch. A withdrawn version otherwise stays bootable with the same keys ([dstack#1297](https://github.com/Dstack-TEE/dstack/issues/1297)).
- **`setRequireTcbUpToDate(true)`** on the `DstackApp`.
- **Freeze (optional, irreversible)**: `disableUpgrades()` only freezes the contract implementation; compose hashes can still be added. Freezing the code set requires `renounceOwnership()` too, after which no version can ever be added or removed ([dstack#1293](https://github.com/Dstack-TEE/dstack/issues/1293)). Only worth it for a finished, audited version.

## The relayer wallet

The relayer key only makes sense for actions the code itself decides. Rules for when those actions are implemented:

- No endpoint signs arbitrary payloads or transactions. Each on-chain action is a specific code path whose inputs are validated in the enclave.
- The wallet holds only the gas it needs. Treat its balance as spendable by a future malicious registered build, and cap it (top up from an external treasury, or pay through an [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) paymaster).
- Contracts that trust the relayer should check its address with the on-chain chain verification above, or through an allowlist updated by the same timelock, so a rotated relayer can be replaced.
- Nonces are managed by a single instance, or by a per-instance domain (`wulong/relayer/evm/v1/<n>`) if several instances must send concurrently.

## Rotation

Rotation means changing the domain version (`/v1` to `/v2`) and bumping `epoch` in the manifest. The new build derives both generations:

- **ML-KEM**: the enclave decapsulates each stored server entry with the old key and re-encapsulates the AES key to the new one, without the plaintext data ever leaving it. Client recipient entries are unaffected. The old derivation is dropped in the next release.
- **Relayer**: the new build sweeps the old wallet's balance to the new address and updates the allowlists.

Rotation limits exposure to a future leak but gives no forward secrecy against a KMS root compromise: the root can derive every past generation.

## Development mode

Outside production, `/var/run/dstack.sock` is replaced by the dstack simulator (`DSTACK_SIMULATOR_ENDPOINT`), which serves `GetKey` with a fixed, public root. The same code path runs everywhere, with no env-key branch.

In production, startup fails if:

- `ADMIN_MLKEM_PRIVATE_KEY`, `ADMIN_MLKEM_PUBLIC_KEY` or any other key material is present in env
- the dstack socket is unreachable, or `/v1/GetKey` is missing
- `DSTACK_SIMULATOR_ENDPOINT` is set

## Implementation outline

A follow-up issue implements this. Expected shape:

- `KeyDerivationService` (`src/keys/`): calls `/v1/GetKey` over the socket (the v1 client is about 30 lines of `http.request` with `socketPath`), derives the three keys once, and exposes only public keys, `decap(ct)` and signing methods. Private keys never leave the service.
- `MlKemEncryptionService` takes the decapsulation capability from it instead of `ConfigService`.
- `SecretsService`'s KMS and env paths for keys, `ADMIN_MLKEM_*` in compose and docs, and `scripts/generate-admin-keypair.ts` for production are removed.
- Attestation (`tee-platform.service.ts`) quotes the `report_data` above, and gains `?nonce=`. It uses `/GetQuote` through the same client, so `@phala/dstack-sdk` is no longer a dependency.
- `scripts/verify-attestation.ts` implements the verification steps.
- Tests pin the v1 test vectors from the dstack spec and an ML-KEM `deriveKeyPair` vector from [NIST ACVP](https://github.com/usnistgov/ACVP-Server).
- Deployment docs cover creating the `DstackApp` on Base, the Safe and timelock setup, and the release checklist.

## Open questions

- Phala Cloud's availability of dstack 0.6 OS images, needed for `/v1/GetKey`. dstack 0.6.0 was released on 2026-09-28. If it is not available yet, either wait, or start on v0 `getKey(path)` with algorithm-specific paths and accept one planned rotation.
- Timelock delay: long enough for users to react, short enough for security fixes. An emergency path could remove compose hashes without delay (removal only ever reduces who holds keys), while additions stay timelocked.
- Whether to self-host a KMS to remove Phala's `DstackKms` ownership from the trust set.

## Sources

- [dstack guest API v1 specification](https://github.com/Dstack-TEE/dstack/blob/master/docs/guest-api-v1.md): KDF, signature chain, verification
- [dstack JS SDK README](https://github.com/Dstack-TEE/dstack/blob/master/sdk/js/README.md): `getKey`, v0 blockchain helpers
- [`DstackKms.sol`](https://github.com/Dstack-TEE/dstack/blob/master/dstack/kms/auth-eth/contracts/DstackKms.sol) and [`DstackApp.sol`](https://github.com/Dstack-TEE/dstack/blob/master/dstack/kms/auth-eth/contracts/DstackApp.sol): on-chain authorization
- [dstack on-chain governance](https://github.com/Dstack-TEE/dstack/blob/master/docs/onchain-governance.md)
- [Dstack: A Zero Trust Framework for Confidential Containers](https://arxiv.org/abs/2509.11555): KMS design and threat model
- [Phala: Get a deterministic key](https://docs.phala.com/phala-cloud/key-management/get-a-key) and [key management protocol](https://docs.phala.com/phala-cloud/key-management/key-management-protocol)
- dstack issues on [root key rotation](https://github.com/Dstack-TEE/dstack/issues/1287), [add-only upgrades](https://github.com/Dstack-TEE/dstack/issues/1297) and [irreversible owner actions](https://github.com/Dstack-TEE/dstack/issues/1293)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- zk-api's [`tee-key-manager.service.ts`](https://github.com/w3hc/zk-api/blob/main/src/attestation/tee-key-manager.service.ts)
