# Wulong Scripts

This directory contains utility scripts for Wulong development and deployment.

## Attestation Verification

### `verify-attestation.ts`

Client-side TEE attestation verification utility for Intel TDX quotes from Phala Network deployments.

**Purpose**: Verify that a Wulong server is running in a genuine Intel TDX TEE environment before sending sensitive data.

**Usage**:

```bash
# Verify live server attestation
pnpm verify:attestation https://your-wulong.phala.network/chest/attestation

# Or verify saved attestation
pnpm verify:attestation attestation.json

# Also check the DstackApp's on-chain governance (BASE_RPC_URL or --rpc, default https://mainnet.base.org)
pnpm verify:attestation <url-or-file> --app <DstackApp> --from-block <app creation block> [--min-delay <seconds>]

# Full path
pnpm ts-node scripts/verify-attestation.ts <url-or-file>
```

**What it verifies**:

✅ Key binding: the quote's `report_data` commits to the returned ML-KEM and identity keys and to a fresh random nonce, and the key manifest is signed by the identity key (see [KEY_DERIVATION.md](../docs/KEY_DERIVATION.md#verification)). It exits with an error if not: do not encrypt to that key.
✅ Platform is Intel TDX (not 'none' mock)
✅ TDX quote structure is valid
✅ Certificate chain is present
✅ Timestamp is fresh (< 5 minutes)
✅ MRTD and RTMR0–3 read from the quote match the returned `measurements`
✅ With `--app`: the key manifest names that app, a `WulongAppOwner` behind a timelock of at least `--min-delay` (7 days) owns it, `requireTcbUpToDate` is set, the running compose hash is allowed, and every compose hash ever allowed is listed (see [GOVERNANCE.md](../docs/GOVERNANCE.md#verifying))

**What it does NOT verify** (requires Intel DCAP or Phala verification service):

❌ Full cryptographic signature verification
❌ TCB (Trusted Computing Base) status
❌ Certificate revocation lists (CRLs)
❌ That RTMR3 is the one replayed from your compose file (see [TEE_SETUP.md](../docs/TEE_SETUP.md#measurements))
❌ The identity key's GetKey signature chain up to the on-chain KMS root

**Example output**:

```
🔍 Wulong TEE Attestation Verifier
═══════════════════════════════════

Fetching attestation from: https://...phala.network/chest/attestation?nonce=...

🔑 Key Binding Check:
✅ report_data commits to the ML-KEM and identity keys
✅ Key manifest signed by the identity key (app 0x...)
✅ The quote carries that report_data

🖥️  Platform Check:
ℹ️    Platform: intel-tdx
✅ Platform is Intel TDX

📦 Quote size: 5010 bytes

🔬 Quote Structure Analysis:
ℹ️    Quote version: 4
ℹ️    TEE type: 0x00000081
✅ TEE type is TDX (0x00000081)

📏 Measurements:
ℹ️    MRTD:  c68518a0...  (dstack OS firmware)
ℹ️    RTMR0: 85e0855a...  (virtual hardware)
ℹ️    RTMR1: 9b43f9f3...  (kernel)
ℹ️    RTMR2: 7cc2dadd...  (kernel cmdline, initrd)
ℹ️    RTMR3: d4e5f6a7...  (app: compose hash)
✅ The returned measurements are the quote's

📜 Certificate Chain (3 certificates):
ℹ️    [0] Intel SGX PCK Certificate
ℹ️        Fingerprint: ef4ba64d...

⏱️  Timestamp Check:
ℹ️    Attestation generated: 2026-03-22T13:57:20.680Z
✅ Timestamp is fresh

📊 Verification Summary:
✅ Key binding: Valid ✓
✅ Platform: Intel TDX ✓
✅ Quote structure: Valid ✓
✅ Certificate chain: Present ✓
✅ Timestamp: Fresh ✓

⚠️  Important Notes:
This is Step 0 (Basic Platform Detection) only.
The script outputs detailed instructions for Steps 1-5:
  1. Verify full cryptographic signatures (Phala verifier or Intel DCAP)
  2. Check TCB (Trusted Computing Base) status
  3. Verify certificate revocation lists (CRLs)
  4. Compare RTMR3 against the value replayed from the compose file
  5. Implement client-side verification before sending secrets
```

**Security considerations**:

- **Basic verification**: This script performs structural validation only
- **Production use**: Integrate with [Intel DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives) or [Phala's verification service](https://docs.phala.com/phala-cloud/attestation/verify-your-application)
- **Measurements**: RTMR3 identifies the app; MRTD and RTMR0–2 identify the dstack OS image. Compare them against values you reproduce, not against values the server returns
- **Freshness**: Attestations older than 5 minutes are flagged as stale

**Next steps after verification**:

1. Reproduce RTMR3 from your `app-compose.json` and the event log, as described in [TEE_SETUP.md](../docs/TEE_SETUP.md#measurements), and publish it with the dstack OS version (which fixes MRTD and RTMR0–2).

2. Implement client-side verification in your application:
   ```typescript
   const attestation = await fetch(
     `https://server/chest/attestation?nonce=${nonce}`,
   ).then((r) => r.json());

   if (attestation.platform !== 'intel-tdx') {
     throw new Error('Server not running in TEE');
   }

   // After verifying the quote signature (Phala verifier or Intel DCAP)
   // and the key binding (src/attestation/key-binding.ts):
   const EXPECTED_RTMR3 = 'd4e5f6a7...'; // Reproduced from app-compose.json
   if (attestation.measurements.rtmr3 !== EXPECTED_RTMR3) {
     throw new Error('Server running unexpected code');
   }
   ```

**Integration with Phala**:

For production deployments on Phala Network, use their verification service:

```typescript
// Verify via Phala's attestation service
const response = await fetch('https://verifier.phala.network/verify', {
  method: 'POST',
  body: JSON.stringify({
    quote: attestation.report,
  })
});

const { valid, tcb_status } = await response.json();
```

See: https://docs.phala.com/phala-cloud/attestation/verify-your-application

---

## Governance

### `governance/propose-release.ts`

Builds the timelock batch that allows a release on the `DstackApp`: it adds the compose hash of the given `app-compose.json` and removes every other allowed one. It writes Safe Transaction Builder files to schedule it, then execute it after the delay. See [GOVERNANCE.md](../docs/GOVERNANCE.md#releases).

```bash
pnpm governance:propose-release app-compose.json --app <DstackApp> --from-block <n> [--rpc <url>] [--out <dir>]
```

---

## Other Scripts

### `test-mlkem-flow.ts`

Tests ML-KEM-1024 quantum-resistant encryption flow.

### `test-mlkem-with-server.ts`

End-to-end test of ML-KEM encryption with running server.
