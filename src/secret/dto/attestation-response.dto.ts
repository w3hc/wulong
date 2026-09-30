import type { SignedKeyManifest } from '../../keys/key-derivation.service';
import type { TdxMeasurements } from '../../attestation/tdx-quote';
import { ApiProperty } from '@nestjs/swagger';

export class AttestationResponseDto {
  @ApiProperty({
    description:
      'intel-tdx on dstack; none outside production when no dstack guest agent is reachable, in which case report is a placeholder',
    enum: ['intel-tdx', 'none'],
    example: 'intel-tdx',
  })
  platform: string;

  @ApiProperty({
    description: 'Base64 TDX v4 quote from the dstack guest agent',
    example: 'BAACAIEAAAAAAAAAk5pyM/ecTKmUCg2zlX8GB...',
  })
  report: string;

  @ApiProperty({
    description:
      'Hex MRTD and RTMR0-3 read from the quote. RTMR3 holds the app compose hash and identifies the app; ' +
      'MRTD and RTMR0-2 identify the dstack OS image. Null when platform is none. See docs/TEE_SETUP.md.',
    nullable: true,
    example: {
      mrtd: 'c68518a0...',
      rtmr0: '85e0855a...',
      rtmr1: '9b43f9f3...',
      rtmr2: '7cc2dadd...',
      rtmr3: 'd4e5f6a7...',
    },
  })
  measurements: TdxMeasurements | null;

  @ApiProperty({
    description:
      'dstack event log (JSON string) that replays RTMR0-3, including the compose-hash event in RTMR3. Null when platform is none.',
    nullable: true,
    type: String,
  })
  eventLog: string | null;

  @ApiProperty({
    description: 'Timestamp when the attestation was generated',
    example: '2026-03-18T10:30:00.000Z',
  })
  timestamp: string;

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
      "Address of the relayer wallet, which sends Wulong's on-chain transactions. Committed to by reportData and the key manifest",
    example: '0x602cA51341d6d1ff32b2ce8442c5e807A527CA17',
  })
  relayerAddress: string;

  @ApiProperty({
    description:
      'Uncompressed secp256k1 relayer public key (hex), of relayerAddress, to check relayerSignatureChain',
    example: '0x04c5d6e7...',
  })
  relayerPublicKey: string;

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

  @ApiProperty({
    description:
      "The relayer key's dstack GetKey signature chain (hex), anchored on the KMS root, so contracts can verify the relayer with ecrecover",
    type: [String],
  })
  relayerSignatureChain: string[];
}
