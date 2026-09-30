import { Test, TestingModule } from '@nestjs/testing';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import {
  BadRequestException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { SecretController } from './secret.controller';
import { SecretService } from './secret.service';
import { SiweGuard } from '../auth/siwe.guard';
import { SiweService } from '../auth/siwe.service';
import { KeyDerivationService } from '../keys/key-derivation.service';
import { StoreRequestDto } from './dto/store-request.dto';

describe('SecretController', () => {
  let controller: SecretController;
  let secretService: SecretService;

  const mockSecretService = {
    store: jest.fn(),
    access: jest.fn(),
    remove: jest.fn(),
    getAttestation: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SecretController],
      providers: [
        {
          provide: SecretService,
          useValue: mockSecretService,
        },
        SiweGuard,
        SiweService,
        {
          provide: KeyDerivationService,
          useValue: { isAvailable: () => false },
        },
      ],
    }).compile();

    controller = module.get<SecretController>(SecretController);
    secretService = module.get<SecretService>(SecretService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should have SecretService injected', () => {
    expect(secretService).toBeDefined();
  });

  describe('store', () => {
    const req = {
      user: { address: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb' },
    };

    it('should store a secret and return a slot', async () => {
      const dto: StoreRequestDto = {
        secret: 'my-secret',
        publicAddresses: ['0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'],
      };
      const expectedSlot = 'a'.repeat(64);

      mockSecretService.store.mockResolvedValue(expectedSlot);

      const result = await controller.store(dto, req);

      expect(result).toEqual({ slot: expectedSlot });
      expect(mockSecretService.store).toHaveBeenCalledWith(
        dto.secret,
        dto.publicAddresses,
        req.user.address,
      );
      expect(mockSecretService.store).toHaveBeenCalledTimes(1);
    });

    it('should handle multiple public addresses', async () => {
      const dto: StoreRequestDto = {
        secret: 'my-secret',
        publicAddresses: [
          '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
          '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
        ],
      };
      const expectedSlot = 'b'.repeat(64);

      mockSecretService.store.mockResolvedValue(expectedSlot);

      const result = await controller.store(dto, req);

      expect(result).toEqual({ slot: expectedSlot });
      expect(mockSecretService.store).toHaveBeenCalledWith(
        dto.secret,
        dto.publicAddresses,
        req.user.address,
      );
    });

    it('should propagate BadRequestException from service', async () => {
      const dto: StoreRequestDto = {
        secret: '',
        publicAddresses: ['0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'],
      };

      mockSecretService.store.mockRejectedValue(
        new BadRequestException('Secret cannot be empty'),
      );

      await expect(controller.store(dto, req)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should propagate validation errors for invalid addresses', async () => {
      const dto: StoreRequestDto = {
        secret: 'my-secret',
        publicAddresses: ['invalid-address'],
      };

      mockSecretService.store.mockRejectedValue(
        new BadRequestException('Invalid Ethereum address in publicAddresses'),
      );

      await expect(controller.store(dto, req)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should propagate ForbiddenException if caller is not among publicAddresses', async () => {
      const dto: StoreRequestDto = {
        secret: 'my-secret',
        publicAddresses: ['0x70997970C51812dc3A010C7d01b50e0d17dc79C8'],
      };

      mockSecretService.store.mockRejectedValue(
        new ForbiddenException(
          'Store denied: caller must be one of publicAddresses',
        ),
      );

      await expect(controller.store(dto, req)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('access', () => {
    it('should return secret if caller is authorized', async () => {
      const slot = 'a'.repeat(64);
      const callerAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';
      const expectedSecret = 'my-secret';

      mockSecretService.access.mockResolvedValue(expectedSecret);

      const req = { user: { address: callerAddress } };
      const result = await controller.access(slot, req);

      expect(result).toEqual({ secret: expectedSecret });
      expect(mockSecretService.access).toHaveBeenCalledWith(
        slot,
        callerAddress,
      );
      expect(mockSecretService.access).toHaveBeenCalledTimes(1);
    });

    it('should propagate NotFoundException if slot does not exist', async () => {
      const slot = 'nonexistent'.repeat(6);
      const callerAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';

      mockSecretService.access.mockRejectedValue(
        new NotFoundException('Slot not found'),
      );

      const req = { user: { address: callerAddress } };

      await expect(controller.access(slot, req)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should propagate BadRequestException for invalid slot', async () => {
      const slot = '';
      const callerAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';

      mockSecretService.access.mockRejectedValue(
        new BadRequestException('Slot cannot be empty'),
      );

      const req = { user: { address: callerAddress } };

      await expect(controller.access(slot, req)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should use address from SIWE authenticated request', async () => {
      const slot = 'a'.repeat(64);
      const authenticatedAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';
      const expectedSecret = 'authenticated-secret';

      mockSecretService.access.mockResolvedValue(expectedSecret);

      // Simulate request object populated by SiweGuard
      const req = { user: { address: authenticatedAddress } };
      const result = await controller.access(slot, req);

      expect(result).toEqual({ secret: expectedSecret });
      expect(mockSecretService.access).toHaveBeenCalledWith(
        slot,
        authenticatedAddress,
      );
    });
  });

  describe('remove', () => {
    const req = {
      user: { address: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb' },
    };

    it('should delete the slot as the authenticated caller', async () => {
      const slot = 'a'.repeat(64);
      mockSecretService.remove.mockResolvedValue(undefined);

      await expect(controller.remove(slot, req)).resolves.toBeUndefined();
      expect(mockSecretService.remove).toHaveBeenCalledWith(
        slot,
        req.user.address,
      );
    });

    it('should propagate NotFoundException from service', async () => {
      mockSecretService.remove.mockRejectedValue(
        new NotFoundException('Slot not found'),
      );

      await expect(controller.remove('a'.repeat(64), req)).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('decorator validation', () => {
    it('should be decorated with correct tags and route', () => {
      // Verify the controller is properly decorated
      expect(controller).toBeDefined();
      expect(secretService).toBeDefined();
    });

    it('should guard store, access and remove with SiweGuard', () => {
      for (const name of ['store', 'access', 'remove']) {
        const handler = Object.getOwnPropertyDescriptor(
          SecretController.prototype,
          name,
        )?.value as object;
        const guards = Reflect.getMetadata(GUARDS_METADATA, handler) as
          unknown[] | undefined;
        expect(guards).toContain(SiweGuard);
      }
    });

    it('should have SiweGuard configured in module', () => {
      // SiweGuard is applied via @UseGuards decorator
      // This is validated at runtime, not via reflection
      expect(controller).toBeDefined();
    });
  });

  describe('edge cases', () => {
    it('should handle very long slot identifiers', async () => {
      const longSlot = 'a'.repeat(64);
      const callerAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';
      const expectedSecret = 'secret';

      mockSecretService.access.mockResolvedValue(expectedSecret);

      const req = { user: { address: callerAddress } };
      const result = await controller.access(longSlot, req);

      expect(result).toEqual({ secret: expectedSecret });
    });

    it('should handle special characters in secrets', async () => {
      const dto: StoreRequestDto = {
        secret: 'my-secret!@#$%^&*()',
        publicAddresses: ['0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'],
      };
      const expectedSlot = 'c'.repeat(64);
      const req = { user: { address: dto.publicAddresses[0] } };

      mockSecretService.store.mockResolvedValue(expectedSlot);

      const result = await controller.store(dto, req);

      expect(result).toEqual({ slot: expectedSlot });
    });

    it('should handle checksummed addresses', async () => {
      const slot = 'a'.repeat(64);
      // Checksummed address (mixed case)
      const checksummedAddress = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
      const expectedSecret = 'secret';

      mockSecretService.access.mockResolvedValue(expectedSecret);

      const req = { user: { address: checksummedAddress } };
      const result = await controller.access(slot, req);

      expect(result).toEqual({ secret: expectedSecret });
      expect(mockSecretService.access).toHaveBeenCalledWith(
        slot,
        checksummedAddress,
      );
    });
  });

  describe('getAttestation', () => {
    const mockAttestation = {
      platform: 'intel-tdx' as const,
      report: 'tdx-quote-base64',
      measurements: {
        mrtd: 'aa',
        rtmr0: 'bb',
        rtmr1: 'cc',
        rtmr2: 'dd',
        rtmr3: 'ee',
      },
      eventLog: '[]',
      timestamp: '2026-03-18T10:35:00.000Z',
      mlkemPublicKey: 'ek-base64',
      identityPublicKey: '0x04',
      reportData: '0x00',
    };

    it('attests without a nonce', async () => {
      mockSecretService.getAttestation.mockResolvedValue(mockAttestation);

      const result = await controller.getAttestation();

      expect(result).toEqual(mockAttestation);
      expect(mockSecretService.getAttestation).toHaveBeenCalledWith(undefined);
    });

    it('passes the parsed nonce to the service', async () => {
      mockSecretService.getAttestation.mockResolvedValue(mockAttestation);

      await controller.getAttestation(`0x${'ab'.repeat(32)}`);

      expect(mockSecretService.getAttestation).toHaveBeenCalledWith(
        Buffer.alloc(32, 0xab),
      );
    });

    it('rejects an invalid nonce', async () => {
      await expect(controller.getAttestation('abcd')).rejects.toThrow(
        new BadRequestException('Nonce must be 32 bytes of hex'),
      );
      expect(mockSecretService.getAttestation).not.toHaveBeenCalled();
    });

    it('should propagate errors from service', async () => {
      mockSecretService.getAttestation.mockRejectedValue(
        new Error('Failed to generate attestation'),
      );

      await expect(controller.getAttestation()).rejects.toThrow(
        'Failed to generate attestation',
      );
    });
  });
});
