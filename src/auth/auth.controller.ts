import { Body, Controller, Post } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { SiweService } from './siwe.service';
import { NonceRequestDto } from './dto/nonce-request.dto';
import { NonceResponseDto } from './dto/nonce-response.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly siweService: SiweService) {}

  @Post('nonce')
  @ApiOperation({
    summary: 'Generate a nonce for SIWE authentication',
    description:
      'Returns a random nonce that must be included in the SIWE message ' +
      'signed by the given address. The nonce is single-use and expires after 5 minutes.',
  })
  @ApiResponse({
    status: 201,
    description: 'Nonce generated successfully',
    type: NonceResponseDto,
  })
  @ApiResponse({
    status: 429,
    description: 'Rate limit exceeded, or too many pending nonces',
  })
  generateNonce(@Body() body: NonceRequestDto): NonceResponseDto {
    const nonce = this.siweService.generateNonce(body.address);
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 minutes

    return {
      nonce,
      issuedAt,
      expiresAt,
    };
  }
}
