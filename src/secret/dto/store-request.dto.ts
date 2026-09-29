import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsIn,
  IsOptional,
  IsString,
  IsArray,
  IsNotEmpty,
  ArrayMinSize,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

/**
 * Multi-recipient ML-KEM encrypted payload
 * Compatible with w3pk's EncryptedPayload format
 */
class RecipientEntry {
  @ApiProperty({
    description: 'Recipient ML-KEM-1024 public key (base64, 1568 bytes)',
    example: 'ZLVMNpXCmEp7vhcylKzGXcx8wVEcaQKI...',
  })
  @IsString()
  @IsNotEmpty()
  publicKey: string;

  @ApiProperty({
    description:
      'ML-KEM-1024 ciphertext for this recipient (base64; v2: 1608 bytes, 1568 KEM + 40 AES-KW wrapped key; v1: 1600 bytes, 1568 KEM + 32 XOR-wrapped key)',
    example: 'k3VARNFcS4hWl6AfR0DMylys...',
  })
  @IsString()
  @IsNotEmpty()
  ciphertext: string;
}

class MultiRecipientEncryptedPayload {
  @ApiPropertyOptional({
    description:
      'Payload format version: 2 (HKDF-derived KEK, AES-KW wrapped key). Omit for legacy v1 payloads.',
    enum: [2],
    example: 2,
  })
  @IsOptional()
  @IsIn([2])
  version?: 2;

  @ApiProperty({
    description: 'Array of recipients (each can decrypt independently)',
    type: [RecipientEntry],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RecipientEntry)
  @ArrayMinSize(1)
  recipients: RecipientEntry[];

  @ApiProperty({
    description:
      'AES-256-GCM encrypted data (base64, shared across all recipients)',
    example: 'J8kl2mN9oP3qR...',
  })
  @IsString()
  @IsNotEmpty()
  encryptedData: string;

  @ApiProperty({
    description: 'AES-256-GCM initialization vector (base64, 12 bytes)',
    example: 'Xy9Zb1cA...',
  })
  @IsString()
  @IsNotEmpty()
  iv: string;

  @ApiProperty({
    description: 'AES-256-GCM authentication tag (base64, 16 bytes)',
    example: 'Mn4Op8Qr...',
  })
  @IsString()
  @IsNotEmpty()
  authTag: string;
}

export class StoreRequestDto {
  @ApiProperty({
    description:
      'Multi-recipient ML-KEM encrypted payload (from w3pk.mlkemEncrypt)',
    type: MultiRecipientEncryptedPayload,
  })
  @IsNotEmpty()
  @ValidateNested()
  @Type(() => MultiRecipientEncryptedPayload)
  secret: MultiRecipientEncryptedPayload;

  @ApiProperty({
    description:
      'Array of Ethereum addresses that can access this secret (via SIWE)',
    example: ['0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'],
    type: [String],
  })
  @IsArray()
  @ArrayMinSize(1)
  @IsString({ each: true })
  publicAddresses: string[];
}
