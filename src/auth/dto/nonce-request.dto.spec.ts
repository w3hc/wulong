import { validate } from 'class-validator';
import { NonceRequestDto } from './nonce-request.dto';

describe('NonceRequestDto', () => {
  it('should validate an Ethereum address', async () => {
    const dto = new NonceRequestDto();
    dto.address = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

    expect(await validate(dto)).toHaveLength(0);
  });

  it('should fail when address is missing', async () => {
    const dto = new NonceRequestDto();

    const errors = await validate(dto);
    expect(errors[0].constraints).toHaveProperty('isEthereumAddress');
  });

  it('should fail when address is not an Ethereum address', async () => {
    const dto = new NonceRequestDto();
    dto.address = '0x1234';

    const errors = await validate(dto);
    expect(errors[0].constraints).toHaveProperty('isEthereumAddress');
  });
});
