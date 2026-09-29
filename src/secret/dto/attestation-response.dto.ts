import type { SignedKeyManifest } from '../../keys/key-derivation.service';
import { ApiProperty } from '@nestjs/swagger';

export class AttestationResponseDto {
  @ApiProperty({
    description: 'TEE platform type',
    enum: ['amd-sev-snp', 'intel-tdx', 'aws-nitro', 'phala', 'none'],
    example: 'amd-sev-snp',
  })
  platform: string;

  @ApiProperty({
    description: 'Base64-encoded attestation report/quote from TEE',
    example: 'eyJhdHRlc3RhdGlvbiI6ICIuLi4ifQ==',
  })
  report: string;

  @ApiProperty({
    description: 'Measurement/hash of the code running in the TEE',
    example: 'a1b2c3d4e5f6...',
  })
  measurement: string;

  @ApiProperty({
    description: 'Timestamp when the attestation was generated',
    example: '2026-03-18T10:30:00.000Z',
  })
  timestamp: string;

  @ApiProperty({
    description: 'Public key of the TEE (if applicable)',
    required: false,
    example: '0x1234567890abcdef...',
  })
  publicKey?: string;

  @ApiProperty({
    description:
      'ML-KEM-1024 public key (base64), derived inside the TEE and committed to by reportData. ' +
      'Clients encrypt secrets to this key after checking the commitment.',
    example: '6RNr8BvBcRe9ivVfuYkN40YCxgE...',
  })
  mlkemPublicKey: string;

  @ApiProperty({
    description:
      'Uncompressed secp256k1 identity public key (hex), which signs the key manifest',
    example: '0x04a1b2c3...',
  })
  identityPublicKey: string;

  @ApiProperty({
    description:
      'Leaf TLS certificate served from inside the enclave (base64 DER), committed to by reportData. ' +
      'Clients check it matches the certificate of their TLS session. Absent when TLS terminates outside the enclave.',
    required: false,
  })
  tlsCertificate?: string;

  @ApiProperty({
    description:
      'The 64 bytes of report_data in the quote (hex): SHA-256 commitment to the public keys and TLS certificate, ' +
      'then the client nonce or zeros. See docs/KEY_DERIVATION.md#report_data.',
    example: '0xab74ab29...',
  })
  reportData: string;

  @ApiProperty({
    description:
      'EIP-712 key manifest signed at boot by the identity key: ' +
      '{ manifest: { appId, mlkemPublicKeyHash, relayer, epoch }, signature }. ' +
      'Domain { name: "Wulong", version: "1" }.',
  })
  keyManifest: SignedKeyManifest;

  @ApiProperty({
    description:
      "The identity key's dstack GetKey signature chain (hex), anchored on the KMS root",
    type: [String],
  })
  identitySignatureChain: string[];
}
