import { ApiProperty } from '@nestjs/swagger';
import { IsEthereumAddress } from 'class-validator';

export class NonceRequestDto {
  @ApiProperty({
    description: 'Ethereum address that will sign the SIWE message',
    example: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
  })
  @IsEthereumAddress()
  address: string;
}
