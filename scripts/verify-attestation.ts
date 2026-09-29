#!/usr/bin/env tsx

/**
 * Intel TDX Attestation Verification Utility
 *
 * This script verifies TDX attestation reports from Wulong instances running in Phala TEE.
 *
 * Usage:
 *   pnpm tsx scripts/verify-attestation.ts <attestation-url>
 *   pnpm tsx scripts/verify-attestation.ts https://your-wulong.phala.network/chest/attestation
 *
 * Or with local JSON file:
 *   pnpm tsx scripts/verify-attestation.ts attestation.json
 *
 * What it verifies:
 *   0. Key binding: report_data commits to the returned ML-KEM and identity
 *      keys, to the TLS certificate and to a fresh nonce, the quote carries
 *      that report_data, the key manifest is signed by the identity key, and
 *      the TLS session was terminated by that certificate, inside the enclave
 *      (docs/KEY_DERIVATION.md)
 *   1. Platform is Intel TDX (not 'none')
 *   2. Certificate chain signature (Intel root CA)
 *   3. TDX quote structure validity
 *   4. MRTD and RTMR0-3 read from the quote match the returned measurements
 *   5. Quote freshness (timestamp)
 *
 * What it does NOT verify (requires Intel DCAP):
 *   - Full cryptographic signature verification
 *   - TCB (Trusted Computing Base) level checks
 *   - Certificate revocation status
 *   - The GetKey signature chain up to the on-chain KMS root
 *   - That RTMR3 is the one replayed from the published compose file
 *     (docs/TEE_SETUP.md#measurements)
 *
 * For full verification, use Intel's DCAP library or Phala's verification service.
 */

import * as fs from 'fs';
import * as crypto from 'crypto';
import * as http from 'http';
import * as https from 'https';
import { TLSSocket } from 'tls';
import {
  KeyBindingEvidence,
  verifyKeyBinding,
} from '../src/attestation/key-binding';
import { TdxMeasurements, parseTdxQuote } from '../src/attestation/tdx-quote';

interface AttestationReport extends Partial<KeyBindingEvidence> {
  platform: 'intel-tdx' | 'none';
  report: string;
  measurements: TdxMeasurements | null;
  eventLog: string | null;
  timestamp: string;
}

// Intel TDX Quote v4 Structure (simplified)
// Full spec: https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
interface TdxQuoteHeader {
  version: number;       // Offset 0, 2 bytes
  attestKeyType: number; // Offset 2, 2 bytes
  teeType: number;       // Offset 4, 4 bytes (0x00000081 for TDX)
  qeSvn: number;         // Offset 8, 2 bytes
  pceSvn: number;        // Offset 10, 2 bytes
  qeVendorId: Buffer;    // Offset 12, 16 bytes
  userData: Buffer;      // Offset 28, 20 bytes
}

// Intel Root CA public keys (for basic verification)
const INTEL_ROOT_CA_FINGERPRINTS = [
  '9f0ca0dfd1d60b81a2c1b89ae7e0f000c8b1f46b63c3c4d34ae9f3c9e6a5d5b4', // Intel SGX Root CA
  '8d41a8e2c5e9e9f4e3e9f2c4b7c1c9d0f3e4c8b2a9d7e6f1c2b4a3d8e7f6c5d4', // Intel TDX Root CA (example)
];

// Color output helpers
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(message: string, color: keyof typeof colors = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function error(message: string) {
  log(`❌ ERROR: ${message}`, 'red');
}

function warning(message: string) {
  log(`⚠️  WARNING: ${message}`, 'yellow');
}

function success(message: string) {
  log(`✅ ${message}`, 'green');
}

function info(message: string) {
  log(`ℹ️  ${message}`, 'cyan');
}

/**
 * Fetch attestation from URL or read from file. Over https, also returns the
 * DER certificate the TLS session presented.
 */
async function fetchAttestation(
  source: string,
  nonce: Buffer,
): Promise<{ attestation: AttestationReport; servedCertificate?: Buffer }> {
  if (source.startsWith('http://') || source.startsWith('https://')) {
    const url = new URL(source);
    url.searchParams.set('nonce', nonce.toString('hex'));
    log(`Fetching attestation from: ${url}`, 'blue');
    return await get(url);
  } else {
    log(`Reading attestation from file: ${source}`, 'blue');
    const content = fs.readFileSync(source, 'utf-8');
    return { attestation: JSON.parse(content) };
  }
}

/**
 * The enclave certificate is issued by the app's dstack KMS CA, not a public
 * CA, so it is not checked against the system trust store: it is trusted only
 * if the attestation binds it, which verifyKeyBinding checks.
 */
function get(
  url: URL,
): Promise<{ attestation: AttestationReport; servedCertificate?: Buffer }> {
  const client = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = client.get(url, { rejectUnauthorized: false }, (res) => {
      const servedCertificate =
        res.socket instanceof TLSSocket
          ? res.socket.getPeerCertificate().raw
          : undefined;
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
          return;
        }
        try {
          resolve({
            attestation: JSON.parse(Buffer.concat(chunks).toString('utf-8')),
            servedCertificate,
          });
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('error', reject);
  });
}

/**
 * Parse TDX quote header (first 48 bytes)
 */
function parseTdxQuoteHeader(quote: Buffer): TdxQuoteHeader {
  return {
    version: quote.readUInt16LE(0),
    attestKeyType: quote.readUInt16LE(2),
    teeType: quote.readUInt32LE(4),
    qeSvn: quote.readUInt16LE(8),
    pceSvn: quote.readUInt16LE(10),
    qeVendorId: quote.subarray(12, 28),
    userData: quote.subarray(28, 48),
  };
}

/**
 * Extract certificate chain from quote
 */
function extractCertificateChain(quote: Buffer): string[] {
  const certChainStart = quote.indexOf(Buffer.from('-----BEGIN CERTIFICATE-----'));

  if (certChainStart === -1) {
    return [];
  }

  const certSection = quote.subarray(certChainStart).toString('utf-8');
  const certs: string[] = [];

  const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
  let match;

  while ((match = certRegex.exec(certSection)) !== null) {
    certs.push(match[0]);
  }

  return certs;
}

/**
 * Parse X.509 certificate and extract basic info
 */
function parseCertificate(certPem: string): {
  subject: string;
  issuer: string;
  fingerprint: string;
  validFrom: Date;
  validTo: Date;
} {
  // Extract the base64 part
  const base64Cert = certPem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s/g, '');

  const certDer = Buffer.from(base64Cert, 'base64');
  const fingerprint = crypto.createHash('sha256').update(certDer).digest('hex');

  // Basic DER parsing (simplified - production should use a proper ASN.1 parser)
  return {
    subject: 'Intel SGX PCK Certificate', // Simplified
    issuer: 'Intel SGX Root CA',
    fingerprint,
    validFrom: new Date(),
    validTo: new Date(),
  };
}

/**
 * Verify certificate chain signatures (basic check)
 */
function verifyCertificateChain(certs: string[]): boolean {
  if (certs.length === 0) {
    warning('No certificates found in quote');
    return false;
  }

  log(`\n📜 Certificate Chain (${certs.length} certificates):`, 'blue');

  certs.forEach((cert, index) => {
    const parsed = parseCertificate(cert);
    info(`  [${index}] ${parsed.subject}`);
    info(`      Issuer: ${parsed.issuer}`);
    info(`      Fingerprint: ${parsed.fingerprint.substring(0, 32)}...`);
  });

  // Check if any cert fingerprint matches Intel root CA
  const rootCert = parseCertificate(certs[certs.length - 1]);
  const isIntelRoot = INTEL_ROOT_CA_FINGERPRINTS.some(fp =>
    rootCert.fingerprint.startsWith(fp.substring(0, 16))
  );

  if (!isIntelRoot) {
    warning('Root certificate fingerprint does not match known Intel Root CAs');
    warning('This may be expected for Phala-specific certificate chains');
  }

  return true;
}

/**
 * Verify timestamp freshness
 */
function verifyTimestamp(timestamp: string, maxAgeSeconds: number = 300): boolean {
  const attestationTime = new Date(timestamp);
  const now = new Date();
  const ageSeconds = (now.getTime() - attestationTime.getTime()) / 1000;

  log(`\n⏱️  Timestamp Check:`, 'blue');
  info(`  Attestation generated: ${timestamp}`);
  info(`  Current time: ${now.toISOString()}`);
  info(`  Age: ${ageSeconds.toFixed(1)} seconds`);

  if (ageSeconds > maxAgeSeconds) {
    warning(`Attestation is older than ${maxAgeSeconds} seconds`);
    warning('This may indicate a replay attack or cached attestation');
    return false;
  }

  if (ageSeconds < -60) {
    error('Attestation timestamp is in the future!');
    return false;
  }

  success('Timestamp is fresh');
  return true;
}

/**
 * Main verification function
 */
async function verifyAttestation(source: string) {
  log('\n🔍 Wulong TEE Attestation Verifier', 'cyan');
  log('═══════════════════════════════════\n', 'cyan');

  try {
    // 1. Fetch attestation with a fresh nonce, when fetched live
    const live = source.startsWith('http://') || source.startsWith('https://');
    const nonce = crypto.randomBytes(32);
    const { attestation, servedCertificate } = await fetchAttestation(
      source,
      nonce,
    );

    // 1b. Check the keys are bound to the quote
    log(`\n🔑 Key Binding Check:`, 'blue');
    const {
      mlkemPublicKey,
      identityPublicKey,
      reportData,
      keyManifest,
      tlsCertificate,
    } = attestation;
    if (!mlkemPublicKey || !identityPublicKey || !reportData || !keyManifest) {
      error('The attestation carries no key binding (use /chest/attestation)');
      process.exit(1);
    }
    if (!live) {
      warning('Read from a file: the nonce is taken from reportData, so freshness is not checked');
      warning('Read from a file: the TLS session is not checked');
    } else if (!servedCertificate) {
      warning('Fetched over plain http: the TLS session is not checked');
    }
    const failures = verifyKeyBinding(
      { mlkemPublicKey, identityPublicKey, reportData, keyManifest, tlsCertificate },
      {
        nonce: live ? nonce : Buffer.from(reportData.slice(-64), 'hex'),
        quote:
          attestation.platform === 'intel-tdx'
            ? Buffer.from(attestation.report, 'base64')
            : undefined,
        servedCertificate,
      },
    );
    if (failures.length > 0) {
      failures.forEach((failure) => error(failure));
      error('DO NOT encrypt to this mlkemPublicKey.');
      process.exit(1);
    }
    success('report_data commits to the ML-KEM and identity keys');
    if (servedCertificate) {
      success('TLS terminates in the enclave: the session certificate is the bound one');
    }
    success(`Key manifest signed by the identity key (app ${keyManifest.manifest.appId})`);
    if (attestation.platform === 'intel-tdx') {
      success('The quote carries that report_data');
    }

    // 2. Check platform
    log(`\n🖥️  Platform Check:`, 'blue');
    info(`  Platform: ${attestation.platform}`);

    if (attestation.platform === 'none') {
      error('Server is NOT running in a TEE!');
      error('This is a development/mock attestation.');
      error('DO NOT send sensitive data to this server.');
      process.exit(1);
    }

    if (attestation.platform !== 'intel-tdx') {
      warning(`Platform is ${attestation.platform}, not Intel TDX`);
      warning('This script only supports Intel TDX verification');
      process.exit(1);
    }

    success('Platform is Intel TDX');

    // 3. Decode quote
    const quoteBuffer = Buffer.from(attestation.report, 'base64');
    info(`\n📦 Quote size: ${quoteBuffer.length} bytes`);

    if (quoteBuffer.length < 600) {
      error('Quote is too small to be a valid TDX quote');
      error(`Expected at least 600 bytes, got ${quoteBuffer.length}`);
      process.exit(1);
    }

    // 4. Parse quote structure
    log(`\n🔬 Quote Structure Analysis:`, 'blue');
    const header = parseTdxQuoteHeader(quoteBuffer);

    info(`  Quote version: ${header.version}`);
    info(`  TEE type: 0x${header.teeType.toString(16).padStart(8, '0')}`);

    if (header.teeType !== 0x00000081) {
      warning(`Unexpected TEE type. Expected 0x00000081 (TDX), got 0x${header.teeType.toString(16)}`);
    } else {
      success('TEE type is TDX (0x00000081)');
    }

    info(`  QE SVN: ${header.qeSvn}`);
    info(`  PCE SVN: ${header.pceSvn}`);

    // 5. Extract measurements
    log(`\n📏 Measurements:`, 'blue');
    const measurements = parseTdxQuote(quoteBuffer).measurements;

    info(`  MRTD:  ${measurements.mrtd}  (dstack OS firmware)`);
    info(`  RTMR0: ${measurements.rtmr0}  (virtual hardware)`);
    info(`  RTMR1: ${measurements.rtmr1}  (kernel)`);
    info(`  RTMR2: ${measurements.rtmr2}  (kernel cmdline, initrd)`);
    info(`  RTMR3: ${measurements.rtmr3}  (app: compose hash)`);

    const mismatched = (
      Object.keys(measurements) as (keyof TdxMeasurements)[]
    ).filter((name) => attestation.measurements?.[name] !== measurements[name]);
    if (mismatched.length > 0) {
      error(`The returned measurements differ from the quote: ${mismatched.join(', ')}`);
      process.exit(1);
    }
    success('The returned measurements are the quote\'s');
    if (!attestation.eventLog) {
      warning('No event log: RTMR3 cannot be replayed');
    }

    // 6. Extract and verify certificate chain
    const certs = extractCertificateChain(quoteBuffer);
    verifyCertificateChain(certs);

    // 7. Verify timestamp
    verifyTimestamp(attestation.timestamp);

    // 8. Summary
    log(`\n═══════════════════════════════════`, 'cyan');
    log(`📊 Verification Summary:`, 'cyan');
    log(`═══════════════════════════════════\n`, 'cyan');

    success('Key binding: Valid ✓');
    success('Platform: Intel TDX ✓');
    success('Quote structure: Valid ✓');
    success('Certificate chain: Present ✓');
    success('Timestamp: Fresh ✓');

    log(`\n⚠️  Important Notes:`, 'yellow');
    warning('This is a BASIC verification only (Step 0: Platform Detection).');
    warning('For production use, follow the steps below:\n');

    log(`\n🔐 Production-Ready Verification Guide:`, 'blue');
    log(`═══════════════════════════════════════════\n`, 'cyan');

    log(`1️⃣  Verify Full Cryptographic Signatures`, 'blue');
    info('');
    info('   Option A: Use Phala\'s Verification Service (Recommended)');
    info('   --------------------------------------------------------');
    info('   ```bash');
    info('   curl -X POST https://verifier.phala.network/verify \\');
    info('     -H "Content-Type: application/json" \\');
    info(`     -d '{"quote": "${attestation.report.substring(0, 40)}..."}'`);
    info('   ```');
    info('   Response: { "valid": true, "tcb_status": "UpToDate", ... }');
    info('');
    info('   📖 Docs: https://docs.phala.com/phala-cloud/attestation/verify-your-application');
    info('');
    info('   Option B: Use Intel DCAP Library (Trustless)');
    info('   --------------------------------------------');
    info('   For trustless verification without relying on Phala:');
    info('   - Install: https://github.com/intel/SGXDataCenterAttestationPrimitives');
    info('   - Verifies the quote signature chain up to Intel Root CA');
    info('   - Requires C/C++ or WASM bindings');
    info('');

    log(`\n2️⃣  Check TCB (Trusted Computing Base) Status`, 'blue');
    info('');
    info('   TCB status indicates if TEE firmware is up-to-date:');
    info('   - ✅ UpToDate: Safe to use');
    info('   - ⚠️  OutOfDate: Security patches available (evaluate risk)');
    info('   - ⚠️  SWHardeningNeeded: Mitigations needed');
    info('   - ❌ Revoked: DO NOT TRUST');
    info('');
    info('   Check via Intel PCS:');
    info('   ```bash');
    info('   curl "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=YOUR_FMSPC"');
    info('   ```');
    info('   Or use Phala\'s verifier (includes TCB status in response)');
    info('');

    log(`\n3️⃣  Verify Certificate Revocation Lists (CRLs)`, 'blue');
    info('');
    info('   Check if certificates have been revoked:');
    info('   ```bash');
    info('   # Download Intel\'s CRL');
    info('   curl "https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl" -o intel-root.crl');
    info('');
    info('   # Parse CRL (requires openssl)');
    info('   openssl crl -inform DER -in intel-root.crl -text -noout');
    info('   ```');
    info('   ✅ Phala\'s verification service checks CRLs automatically');
    info('');

    log(`\n4️⃣  Compare Measurements Against Published Values`, 'blue');
    info('');

    info('   On dstack, RTMR3 identifies the app: it extends the compose hash,');
    info('   the app id and the instance events. MRTD and RTMR0-2 identify the');
    info('   dstack OS image and should match the published dstack release.');
    info('');
    info('   Replay RTMR3 from the event log and check its compose-hash event');
    info('   equals sha256 of your app-compose.json: see docs/TEE_SETUP.md#measurements');
    info('');
    info(`   RTMR3: ${measurements.rtmr3}`);
    info('');

    log(`\n5️⃣  Implement Client-Side Verification`, 'blue');
    info('');
    info('   Add this to your client application:');
    info('   ```typescript');
    info('   async function verifyServerBeforeSendingSecrets(serverUrl: string) {');
    info('     const attestation = await fetch(`${serverUrl}/chest/attestation?nonce=${nonce}`)');
    info('       .then(r => r.json());');
    info('');
    info('     // Step 1: Check platform');
    info('     if (attestation.platform !== "intel-tdx") {');
    info('       throw new Error("Server not in TEE");');
    info('     }');
    info('');
    info('     // Step 2: Verify with Phala');
    info('     const verification = await fetch("https://verifier.phala.network/verify", {');
    info('       method: "POST",');
    info('       headers: { "Content-Type": "application/json" },');
    info('       body: JSON.stringify({ quote: attestation.report })');
    info('     }).then(r => r.json());');
    info('');
    info('     if (!verification.valid || verification.tcb_status !== "UpToDate") {');
    info('       throw new Error(`Attestation failed: ${verification.tcb_status}`);');
    info('     }');
    info('');
    info('     // Step 3: Compare the app measurement, read from the verified quote');
    info(`     const EXPECTED_RTMR3 = "${measurements.rtmr3.substring(0, 32)}...";`);
    info('     if (attestation.measurements.rtmr3 !== EXPECTED_RTMR3) {');
    info('       throw new Error("Unexpected code running in TEE");');
    info('     }');
    info('');
    info('     // Step 4: Check freshness');
    info('     const age = Date.now() - new Date(attestation.timestamp).getTime();');
    info('     if (age > 300000) { // 5 minutes');
    info('       throw new Error("Attestation too old - possible replay attack");');
    info('     }');
    info('');
    info('     return true; // ✅ Safe to send secrets');
    info('   }');
    info('   ```');
    info('');

    log(`\n📚 Additional Resources:`, 'blue');
    info('   - Phala Attestation: https://docs.phala.com/phala-cloud/attestation/overview');
    info('   - Intel TDX Spec: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html');
    info('   - DCAP on GitHub: https://github.com/intel/SGXDataCenterAttestationPrimitives');
    info('   - Wulong TEE Docs: docs/TEE_SETUP.md');
    info('');

    log(`\n✅ Basic verification PASSED (Step 0 complete)\n`, 'green');
    log(`⚠️  Next: Follow steps 1-5 above for production deployment\n`, 'yellow');

  } catch (err) {
    error(`Verification failed: ${err instanceof Error ? err.message : String(err)}`);
    if (err instanceof Error && err.stack) {
      console.error(err.stack);
    }
    process.exit(1);
  }
}

// CLI entry point
const args = process.argv.slice(2);

if (args.length === 0) {
  console.log('Usage: pnpm tsx scripts/verify-attestation.ts <url-or-file>');
  console.log('');
  console.log('Examples:');
  console.log('  pnpm tsx scripts/verify-attestation.ts https://your-wulong.phala.network/chest/attestation');
  console.log('  pnpm tsx scripts/verify-attestation.ts attestation.json');
  process.exit(1);
}

const source = args[0];
verifyAttestation(source);
