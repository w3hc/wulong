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

# Full path
pnpm ts-node scripts/verify-attestation.ts <url-or-file>
```

**What it verifies**:

✅ Key binding: the quote's `report_data` commits to the returned ML-KEM and identity keys and to a fresh random nonce, and the key manifest is signed by the identity key (see [KEY_DERIVATION.md](../docs/KEY_DERIVATION.md#verification)). It exits with an error if not: do not encrypt to that key.
✅ Platform is Intel TDX (not 'none' mock)
✅ TDX quote structure is valid
✅ Certificate chain is present
✅ Timestamp is fresh (< 5 minutes)
✅ MRTD measurement extraction

**What it does NOT verify** (requires Intel DCAP or Phala verification service):

❌ Full cryptographic signature verification
❌ TCB (Trusted Computing Base) status
❌ Certificate revocation lists (CRLs)
❌ Comparison against known good measurement
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
ℹ️    MRTD (Measurement of TD):
ℹ️      a1b2c3d4e5f6...

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
  4. Compare RTMR2/RTMR3 measurements against published values
  5. Implement client-side verification before sending secrets
```

**Security considerations**:

- **Basic verification**: This script performs structural validation only
- **Production use**: Integrate with [Intel DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives) or [Phala's verification service](https://docs.phala.com/phala-cloud/attestation/verify-your-application)
- **MRTD comparison**: You must compare the extracted MRTD against your published measurement
- **Freshness**: Attestations older than 5 minutes are flagged as stale

**Next steps after verification**:

1. Save the MRTD measurement:
   ```bash
   pnpm verify:attestation https://your-server/chest/attestation | grep "MRTD" > measurement.txt
   ```

2. Publish the expected measurement in your project documentation

3. Implement client-side verification in your application:
   ```typescript
   import { verifyAttestation } from './verify-attestation';

   const attestation = await fetch('https://server/attestation').then(r => r.json());

   // Basic check
   if (attestation.platform !== 'intel-tdx') {
     throw new Error('Server not running in TEE');
   }

   // Compare MRTD
   const EXPECTED_MRTD = 'a1b2c3d4e5f6...'; // Published measurement
   if (attestation.measurement !== EXPECTED_MRTD) {
     throw new Error('Server running unexpected code');
   }

   // Now safe to send secrets
   await sendSecret(data);
   ```

**Integration with Phala**:

For production deployments on Phala Network, use their verification service:

```typescript
// Verify via Phala's attestation service
const response = await fetch('https://verifier.phala.network/verify', {
  method: 'POST',
  body: JSON.stringify({
    quote: attestation.report,
    expected_measurement: YOUR_PUBLISHED_MRTD
  })
});

const { valid, tcb_status } = await response.json();
```

See: https://docs.phala.com/phala-cloud/attestation/verify-your-application

---

## Other Scripts

### `test-mlkem-flow.ts`

Tests ML-KEM-1024 quantum-resistant encryption flow.

### `test-mlkem-with-server.ts`

End-to-end test of ML-KEM encryption with running server.
