import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  UseGuards,
  Req,
  Query,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiSecurity,
  ApiHeader,
  ApiQuery,
} from '@nestjs/swagger';
import { SecretService } from './secret.service';
import { SiweGuard } from '../auth/siwe.guard';
import { StoreRequestDto } from './dto/store-request.dto';
import { StoreResponseDto } from './dto/store-response.dto';
import { AccessResponseDto } from './dto/access-response.dto';
import { AttestationResponseDto } from './dto/attestation-response.dto';
import { parseNonce } from '../attestation/report-data';

@ApiTags('App')
@Controller('chest')
export class SecretController {
  constructor(private readonly secretService: SecretService) {}

  @Post('store')
  @UseGuards(SiweGuard)
  @ApiSecurity('SIWE')
  @ApiOperation({
    summary: 'Store a multi-recipient encrypted secret',
    description:
      'Stores a multi-recipient ML-KEM encrypted secret (from w3pk.mlkemEncrypt) and returns a unique slot identifier. ' +
      'The encrypted payload must include the server as one of the recipients (use mlkemPublicKey from /chest/attestation). ' +
      'Access is controlled via SIWE authentication (publicAddresses). ' +
      'Requires SIWE authentication; the caller must be one of publicAddresses. ' +
      'CRITICAL: Verify attestation before encrypting!',
  })
  @ApiHeader({
    name: 'x-siwe-message',
    description: 'The SIWE message string (base64 encoded)',
    required: true,
  })
  @ApiHeader({
    name: 'x-siwe-signature',
    description: 'The signature hex string',
    required: true,
  })
  @ApiResponse({
    status: 201,
    description: 'Secret stored successfully',
    type: StoreResponseDto,
  })
  @ApiResponse({
    status: 400,
    description:
      'Invalid request - invalid encrypted payload, missing recipients, or invalid addresses',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - missing or invalid SIWE authentication',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - caller is not one of publicAddresses',
  })
  async store(
    @Body() dto: StoreRequestDto,
    @Req() req: { user: { address: string } },
  ): Promise<StoreResponseDto> {
    const slot = await this.secretService.store(
      dto.secret,
      dto.publicAddresses,
      req.user.address,
    );
    return { slot };
  }

  @Get('access/:slot')
  @UseGuards(SiweGuard)
  @ApiSecurity('SIWE')
  @ApiOperation({
    summary: 'Access a secret (server-side decryption)',
    description:
      'Retrieves and decrypts a secret if the authenticated caller is one of the owners. ' +
      'Server performs ML-KEM decryption using its private key (one of the recipients). ' +
      'Returns plaintext secret. ' +
      'Requires SIWE authentication via X-SIWE-Message and X-SIWE-Signature headers. ' +
      'NOTE: Client can also decrypt locally using w3pk.mlkemDecrypt without involving the server.',
  })
  @ApiHeader({
    name: 'x-siwe-message',
    description: 'The SIWE message string (base64 encoded)',
    required: true,
  })
  @ApiHeader({
    name: 'x-siwe-signature',
    description: 'The signature hex string',
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: 'Secret decrypted successfully (plaintext)',
    type: AccessResponseDto,
  })
  @ApiResponse({
    status: 400,
    description:
      'Bad request - ML-KEM decryption failed or server not in recipients list',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - missing or invalid SIWE authentication',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - caller is not an owner of this secret',
  })
  @ApiResponse({
    status: 404,
    description: 'Not found - slot does not exist',
  })
  async access(
    @Param('slot') slot: string,
    @Req() req: { user: { address: string } },
  ): Promise<AccessResponseDto> {
    const secret = await this.secretService.access(slot, req.user.address);
    return { secret };
  }

  @Get('attestation')
  @ApiOperation({
    summary: 'Get TEE attestation binding the ML-KEM public key',
    description:
      "Returns a TEE attestation whose report_data commits to the server's ML-KEM-1024 and identity public keys " +
      'and to the client nonce, along with those keys. ' +
      'CRITICAL: Clients MUST verify the quote and recompute report_data before encrypting data! ' +
      'Use the mlkemPublicKey to encrypt secrets with w3pk.mlkemEncrypt([serverPublicKey]).',
  })
  @ApiQuery({
    name: 'nonce',
    required: false,
    description:
      '32-byte client challenge as hex, placed in report_data[32..64] for freshness',
  })
  @ApiResponse({
    status: 200,
    description: 'Attestation report with the committed public keys',
    type: AttestationResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid nonce',
  })
  @ApiResponse({
    status: 503,
    description: 'Encryption keys are unavailable',
  })
  @ApiResponse({
    status: 500,
    description: 'Failed to generate attestation report',
  })
  async getAttestation(
    @Query('nonce') nonce?: string,
  ): Promise<AttestationResponseDto> {
    let parsed: Buffer | undefined;
    try {
      parsed = parseNonce(nonce);
    } catch (error) {
      throw new BadRequestException((error as Error).message);
    }
    return await this.secretService.getAttestation(parsed);
  }
}
