import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  HttpStatus,
  ServiceUnavailableException,
} from '@nestjs/common';
import { SecretService } from './secret.service';
import { TeePlatformService } from '../attestation/tee-platform.service';
import { buildReportData } from '../attestation/report-data';
import { KeyDerivationService } from '../keys/key-derivation.service';
import { MlKemEncryptionService } from '../encryption/mlkem-encryption.service';
import * as fs from 'fs';
import * as path from 'path';
import * as ethers from 'ethers';

// Mock fs module with promises
jest.mock('fs', () => ({
  existsSync: jest.fn(),
  promises: {
    readFile: jest.fn(),
    writeFile: jest.fn(),
    rename: jest.fn(),
  },
}));

// Mock ethers module
jest.mock('ethers', () => ({
  isAddress: jest.fn(),
}));

describe('SecretService', () => {
  let service: SecretService;
  const testChestPath = path.join(process.cwd(), 'chest.json');

  const mockTeePlatformService = {
    generateAttestationReport: jest.fn(),
    getPlatform: jest.fn(),
    isInTee: jest.fn(),
  };

  const mockMlKemEncryptionService = {
    decrypt: jest.fn(),
    encrypt: jest.fn(),
    getPublicKey: jest.fn(),
    isAvailable: jest.fn(),
    decryptMultiRecipient: jest.fn(),
  };

  const mlkemPublicKey = new Uint8Array(1568).fill(0x01);
  const identityPublicKey = new Uint8Array(65).fill(0x04);

  const keyManifest = {
    manifest: {
      appId: '0x1111111111111111111111111111111111111111',
      mlkemPublicKeyHash: '0x' + '22'.repeat(32),
      relayer: '0x0000000000000000000000000000000000000000',
      epoch: 1,
    },
    signature: '0x' + '33'.repeat(65),
  };

  const mockKeyDerivationService = {
    getMlKemPublicKey: jest.fn(),
    getIdentityPublicKey: jest.fn(),
    getKeyManifest: jest.fn(),
    getIdentitySignatureChain: jest.fn(),
  };

  // Helper to create a valid encrypted payload
  const createMockEncryptedPayload = (publicKey?: string) => {
    // Create 1600 bytes of data (1568 KEM + 32 encrypted AES key)
    const ciphertextBytes = Buffer.alloc(1600);
    // Fill with some data
    for (let i = 0; i < 1600; i++) {
      ciphertextBytes[i] = i % 256;
    }

    return {
      recipients: [
        {
          publicKey: publicKey || Buffer.alloc(1568, 'a').toString('base64'),
          ciphertext: ciphertextBytes.toString('base64'),
        },
      ],
      encryptedData: Buffer.alloc(100, 'e').toString('base64'),
      iv: Buffer.alloc(12, 'i').toString('base64'),
      authTag: Buffer.alloc(16, 't').toString('base64'),
    };
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SecretService,
        {
          provide: TeePlatformService,
          useValue: mockTeePlatformService,
        },
        {
          provide: MlKemEncryptionService,
          useValue: mockMlKemEncryptionService,
        },
        {
          provide: KeyDerivationService,
          useValue: mockKeyDerivationService,
        },
      ],
    }).compile();

    service = module.get<SecretService>(SecretService);

    // Reset mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('store', () => {
    beforeEach(() => {
      // Mock fs.existsSync to return false (no existing chest.json)
      jest.spyOn(fs, 'existsSync').mockReturnValue(false);
      // Mock fs.promises.writeFile
      jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();
      jest.spyOn(fs.promises, 'rename').mockResolvedValue();
      // Mock isAddress
      (ethers.isAddress as unknown as jest.Mock).mockImplementation(
        (address: string) => {
          if (typeof address !== 'string' || !address.startsWith('0x')) {
            return false;
          }
          const hexPart = address.slice(2);
          return hexPart.length === 40 && /^[0-9a-fA-F]+$/.test(hexPart);
        },
      );
      // Mock ML-KEM encryption service availability
      mockMlKemEncryptionService.isAvailable.mockReturnValue(true);
    });

    it('should store a secret and return a slot', async () => {
      const encryptedPayload = createMockEncryptedPayload();
      const publicAddresses = ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'];

      const slot = await service.store(
        encryptedPayload,
        publicAddresses,
        publicAddresses[0],
      );

      expect(slot).toBeDefined();
      expect(typeof slot).toBe('string');
      expect(slot).toMatch(/^[0-9a-f]{64}$/); // 32 bytes hex = 64 chars
    });

    it('should throw BadRequestException if payload is invalid', async () => {
      await expect(
        service.store(
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          null as any,
          ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow(BadRequestException);

      await expect(
        service.store(
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          { recipients: [] } as any,
          ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException if publicAddresses is empty', async () => {
      const encryptedPayload = createMockEncryptedPayload();
      await expect(
        service.store(
          encryptedPayload,
          [],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for invalid Ethereum address', async () => {
      const encryptedPayload = createMockEncryptedPayload();
      await expect(
        service.store(encryptedPayload, ['invalid-address'], 'invalid-address'),
      ).rejects.toThrow(BadRequestException);

      await expect(
        service.store(encryptedPayload, ['0x123'], '0x123'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should accept multiple valid Ethereum addresses', async () => {
      const encryptedPayload = createMockEncryptedPayload();
      const publicAddresses = [
        '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      ];

      const slot = await service.store(
        encryptedPayload,
        publicAddresses,
        publicAddresses[0],
      );

      expect(slot).toBeDefined();
      expect(fs.promises.writeFile).toHaveBeenCalled();
    });

    it('should normalize addresses to lowercase', async () => {
      const encryptedPayload = createMockEncryptedPayload();
      const publicAddresses = ['0xBFBAA5A59E3B6C06AFF9C975092B8705F804FA1C'];

      await service.store(
        encryptedPayload,
        publicAddresses,
        publicAddresses[0],
      );

      const writeCall = (fs.promises.writeFile as jest.Mock).mock
        .calls[0] as unknown[];
      const writtenData = JSON.parse(writeCall[1] as string) as Record<
        string,
        { encryptedPayload: any; publicAddresses: string[] }
      >;
      const slots = Object.values(writtenData);

      expect(slots[0].publicAddresses[0]).toBe(
        '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
      );
    });

    it('should load existing chest data before storing', async () => {
      const existingPayload = createMockEncryptedPayload();
      const existingData = {
        existingSlot: {
          encryptedPayload: existingPayload,
          publicAddresses: ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
        },
      };

      jest.spyOn(fs, 'existsSync').mockReturnValue(true);
      jest
        .spyOn(fs.promises, 'readFile')
        .mockResolvedValue(JSON.stringify(existingData));

      const newPayload = createMockEncryptedPayload();
      const publicAddresses = ['0x70997970C51812dc3A010C7d01b50e0d17dc79C8'];

      await service.store(newPayload, publicAddresses, publicAddresses[0]);

      const writeCall = (fs.promises.writeFile as jest.Mock).mock
        .calls[0] as unknown[];
      const writtenData = JSON.parse(writeCall[1] as string) as Record<
        string,
        unknown
      >;

      // Should contain both old and new entries
      expect(Object.keys(writtenData)).toContain('existingSlot');
      expect(Object.keys(writtenData).length).toBe(2);
    });

    it('should write to a temp file and rename it over the chest', async () => {
      const encryptedPayload = createMockEncryptedPayload();
      const address = '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c';

      await service.store(encryptedPayload, [address], address);

      expect(fs.promises.writeFile).toHaveBeenCalledWith(
        `${testChestPath}.tmp`,
        expect.any(String),
        { encoding: 'utf-8', flush: true },
      );
      expect(fs.promises.rename).toHaveBeenCalledWith(
        `${testChestPath}.tmp`,
        testChestPath,
      );
    });

    it('should not lose writes when stores run concurrently', async () => {
      let onDisk: string | undefined;
      jest.spyOn(fs, 'existsSync').mockImplementation(() => !!onDisk);
      jest
        .spyOn(fs.promises, 'readFile')
        .mockImplementation(() => Promise.resolve(onDisk as string));
      jest.spyOn(fs.promises, 'writeFile').mockImplementation((_path, data) => {
        onDisk = data as string;
        return Promise.resolve();
      });

      const address = '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c';
      const slots = await Promise.all(
        Array.from({ length: 5 }, () =>
          service.store(createMockEncryptedPayload(), [address], address),
        ),
      );

      const stored = JSON.parse(onDisk as string) as Record<string, unknown>;
      expect(Object.keys(stored).sort()).toEqual([...slots].sort());
    });

    it('should keep storing after a failed write', async () => {
      jest
        .spyOn(fs.promises, 'writeFile')
        .mockRejectedValueOnce(new Error('Write error'));

      const address = '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c';
      await expect(
        service.store(createMockEncryptedPayload(), [address], address),
      ).rejects.toThrow('Failed to save secret');
      await expect(
        service.store(createMockEncryptedPayload(), [address], address),
      ).resolves.toEqual(expect.any(String));
    });

    it('should reject with 507 when the chest would exceed CHEST_MAX_BYTES', async () => {
      process.env.CHEST_MAX_BYTES = '100';
      const smallService = new SecretService(
        mockTeePlatformService as unknown as TeePlatformService,
        mockMlKemEncryptionService as unknown as MlKemEncryptionService,
      );
      delete process.env.CHEST_MAX_BYTES;

      const address = '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c';
      await expect(
        smallService.store(createMockEncryptedPayload(), [address], address),
      ).rejects.toMatchObject({ status: HttpStatus.INSUFFICIENT_STORAGE });
      expect(fs.promises.writeFile).not.toHaveBeenCalled();
      expect(fs.promises.rename).not.toHaveBeenCalled();
    });

    it('should write to CHEST_PATH when set', async () => {
      process.env.CHEST_PATH = '/data/chest.json';
      const configuredService = new SecretService(
        mockTeePlatformService as unknown as TeePlatformService,
        mockMlKemEncryptionService as unknown as MlKemEncryptionService,
      );
      delete process.env.CHEST_PATH;

      const address = '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c';
      await configuredService.store(
        createMockEncryptedPayload(),
        [address],
        address,
      );

      expect(fs.promises.rename).toHaveBeenCalledWith(
        '/data/chest.json.tmp',
        '/data/chest.json',
      );
    });

    it('should throw error if file write fails', async () => {
      jest
        .spyOn(fs.promises, 'writeFile')
        .mockRejectedValue(new Error('Write error'));

      const encryptedPayload = createMockEncryptedPayload();
      await expect(
        service.store(
          encryptedPayload,
          ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow('Failed to save secret');
    });

    it('should throw BadRequestException when ML-KEM encryption is not available', async () => {
      mockMlKemEncryptionService.isAvailable.mockReturnValue(false);
      const encryptedPayload = createMockEncryptedPayload();

      await expect(
        service.store(
          encryptedPayload,
          ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow(
        'ML-KEM encryption not configured on server. Contact administrator.',
      );
    });

    it('should throw BadRequestException for invalid ciphertext size', async () => {
      const invalidPayload = createMockEncryptedPayload();
      invalidPayload.recipients[0].ciphertext =
        Buffer.alloc(100).toString('base64'); // Invalid size

      await expect(
        service.store(
          invalidPayload,
          ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow(/Invalid ML-KEM ciphertext size/);
    });

    it('should throw ForbiddenException if caller is not among publicAddresses', async () => {
      const encryptedPayload = createMockEncryptedPayload();

      await expect(
        service.store(
          encryptedPayload,
          ['0x70997970C51812dc3A010C7d01b50e0d17dc79C8'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow(ForbiddenException);
      expect(fs.promises.writeFile).not.toHaveBeenCalled();
    });

    it('should match caller against publicAddresses case-insensitively', async () => {
      const encryptedPayload = createMockEncryptedPayload();

      const slot = await service.store(
        encryptedPayload,
        ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
        '0xBFBAA5A59E3B6C06AFF9C975092B8705F804FA1C',
      );

      expect(slot).toBeDefined();
    });
  });

  describe('access', () => {
    const testSlot = 'a'.repeat(64);
    const testAddress = '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c';
    const testSecret = 'my-secret';

    beforeEach(() => {
      const mockEncryptedPayload = createMockEncryptedPayload();
      const mockData = {
        [testSlot]: {
          encryptedPayload: mockEncryptedPayload,
          publicAddresses: [testAddress.toLowerCase()],
        },
      };

      jest.spyOn(fs, 'existsSync').mockReturnValue(true);
      jest
        .spyOn(fs.promises, 'readFile')
        .mockResolvedValue(JSON.stringify(mockData));
      // Mock isAddress
      (ethers.isAddress as unknown as jest.Mock).mockImplementation(
        (address: string) => {
          if (typeof address !== 'string' || !address.startsWith('0x')) {
            return false;
          }
          const hexPart = address.slice(2);
          return hexPart.length === 40 && /^[0-9a-fA-F]+$/.test(hexPart);
        },
      );
      // Mock ML-KEM encryption service availability
      mockMlKemEncryptionService.isAvailable.mockReturnValue(true);
      // Mock decryption
      mockMlKemEncryptionService.decryptMultiRecipient.mockResolvedValue(
        testSecret,
      );
    });

    it('should return secret if caller is owner', async () => {
      const secret = await service.access(testSlot, testAddress);

      expect(secret).toBe(testSecret);
    });

    it('should be case-insensitive for address comparison', async () => {
      const upperCaseAddress = '0xBFBAA5A59E3B6C06AFF9C975092B8705F804FA1C';
      const secret = await service.access(testSlot, upperCaseAddress);

      expect(secret).toBe(testSecret);
    });

    it('should throw BadRequestException if slot is empty', async () => {
      await expect(service.access('', testAddress)).rejects.toThrow(
        BadRequestException,
      );

      await expect(service.access('   ', testAddress)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw BadRequestException if caller address is invalid', async () => {
      await expect(service.access(testSlot, 'invalid-address')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw NotFoundException if slot does not exist', async () => {
      const nonExistentSlot = 'b'.repeat(64);

      await expect(
        service.access(nonExistentSlot, testAddress),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException if caller is not an owner', async () => {
      const unauthorizedAddress = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

      await expect(
        service.access(testSlot, unauthorizedAddress),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should allow access if caller is one of multiple owners', async () => {
      const address1 = '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c';
      const address2 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

      const mockEncryptedPayload = createMockEncryptedPayload();
      const mockData = {
        [testSlot]: {
          encryptedPayload: mockEncryptedPayload,
          publicAddresses: [address1.toLowerCase(), address2.toLowerCase()],
        },
      };

      jest
        .spyOn(fs.promises, 'readFile')
        .mockResolvedValue(JSON.stringify(mockData));

      // Both owners should be able to access
      const secret1 = await service.access(testSlot, address1);
      expect(secret1).toBe(testSecret);

      const secret2 = await service.access(testSlot, address2);
      expect(secret2).toBe(testSecret);
    });

    it('should throw error if file read fails', async () => {
      jest
        .spyOn(fs.promises, 'readFile')
        .mockRejectedValue(new Error('Read error'));

      await expect(service.access(testSlot, testAddress)).rejects.toThrow(
        'Failed to load secret',
      );
    });

    it('should return empty object if chest.json does not exist', async () => {
      jest.spyOn(fs, 'existsSync').mockReturnValue(false);

      await expect(service.access(testSlot, testAddress)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw BadRequestException when ML-KEM encryption is not available during access', async () => {
      mockMlKemEncryptionService.isAvailable.mockReturnValue(false);

      await expect(service.access(testSlot, testAddress)).rejects.toThrow(
        'ML-KEM encryption not configured on server',
      );
    });

    it('should throw BadRequestException if decryption fails', async () => {
      mockMlKemEncryptionService.decryptMultiRecipient.mockImplementation(
        () => {
          throw new Error('Decryption failed');
        },
      );

      await expect(service.access(testSlot, testAddress)).rejects.toThrow(
        /Failed to decrypt secret/,
      );
    });

    it('should handle ENOENT error when loading secret', async () => {
      const enoentError = new Error('File not found') as NodeJS.ErrnoException;
      enoentError.code = 'ENOENT';
      jest.spyOn(fs.promises, 'readFile').mockRejectedValue(enoentError);

      await expect(service.access(testSlot, testAddress)).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('edge cases', () => {
    beforeEach(() => {
      // Mock isAddress for all edge case tests
      (ethers.isAddress as unknown as jest.Mock).mockImplementation(
        (address: string) => {
          if (typeof address !== 'string' || !address.startsWith('0x')) {
            return false;
          }
          const hexPart = address.slice(2);
          return hexPart.length === 40 && /^[0-9a-fA-F]+$/.test(hexPart);
        },
      );
      // Mock ML-KEM encryption service availability
      mockMlKemEncryptionService.isAvailable.mockReturnValue(true);
    });

    it('should handle checksummed Ethereum addresses', async () => {
      jest.spyOn(fs, 'existsSync').mockReturnValue(false);
      jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();

      // This is a checksummed address (mixed case)
      const checksummedAddress = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
      const encryptedPayload = createMockEncryptedPayload();

      const slot = await service.store(
        encryptedPayload,
        [checksummedAddress],
        checksummedAddress,
      );

      expect(slot).toBeDefined();
    });

    it('should handle encrypted payloads with multiple recipients', async () => {
      jest.spyOn(fs, 'existsSync').mockReturnValue(false);
      jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();

      const multiRecipientPayload = {
        recipients: [
          {
            publicKey: Buffer.alloc(1568, 'a').toString('base64'),
            ciphertext: Buffer.alloc(1600, 0).toString('base64'),
          },
          {
            publicKey: Buffer.alloc(1568, 'b').toString('base64'),
            ciphertext: Buffer.alloc(1600, 1).toString('base64'),
          },
        ],
        encryptedData: Buffer.alloc(100, 'e').toString('base64'),
        iv: Buffer.alloc(12, 'i').toString('base64'),
        authTag: Buffer.alloc(16, 't').toString('base64'),
      };

      const slot = await service.store(
        multiRecipientPayload,
        ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
        '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
      );

      expect(slot).toBeDefined();
    });

    it('should store encrypted payload correctly', async () => {
      jest.spyOn(fs, 'existsSync').mockReturnValue(false);
      jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();

      const encryptedPayload = createMockEncryptedPayload();
      const slot = await service.store(
        encryptedPayload,
        ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
        '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
      );

      expect(slot).toBeDefined();

      // Verify the encrypted payload was stored correctly
      const writeCall = (fs.promises.writeFile as jest.Mock).mock
        .calls[0] as unknown[];
      const writtenData = JSON.parse(writeCall[1] as string) as Record<
        string,
        { encryptedPayload: any; publicAddresses: string[] }
      >;
      expect(writtenData[slot].encryptedPayload).toEqual(encryptedPayload);
    });
  });

  describe('getAttestation', () => {
    const mockAttestation = {
      platform: 'intel-tdx' as const,
      report: 'tdx-quote-base64',
      measurement: 'def456measurement',
      timestamp: '2026-03-18T10:35:00.000Z',
    };

    beforeEach(() => {
      mockKeyDerivationService.getMlKemPublicKey.mockReturnValue(
        mlkemPublicKey,
      );
      mockKeyDerivationService.getIdentityPublicKey.mockReturnValue(
        identityPublicKey,
      );
      mockKeyDerivationService.getKeyManifest.mockReturnValue(keyManifest);
      mockKeyDerivationService.getIdentitySignatureChain.mockReturnValue([
        new Uint8Array([0xaa, 0xbb]),
        new Uint8Array([0xcc]),
      ]);
      mockTeePlatformService.generateAttestationReport.mockResolvedValue(
        mockAttestation,
      );
    });

    it('quotes the report_data committing to the keys', async () => {
      const expected = buildReportData({ mlkemPublicKey, identityPublicKey });

      const result = await service.getAttestation();

      expect(
        mockTeePlatformService.generateAttestationReport,
      ).toHaveBeenCalledWith(expected);
      expect(result).toEqual({
        ...mockAttestation,
        publicKey: undefined,
        mlkemPublicKey: Buffer.from(mlkemPublicKey).toString('base64'),
        identityPublicKey: `0x${Buffer.from(identityPublicKey).toString('hex')}`,
        reportData: `0x${expected.toString('hex')}`,
        keyManifest,
        identitySignatureChain: ['0xaabb', '0xcc'],
      });
    });

    it('places the client nonce in report_data', async () => {
      const nonce = Buffer.alloc(32, 0x7f);

      const result = await service.getAttestation(nonce);

      const [reportData] = mockTeePlatformService.generateAttestationReport.mock
        .calls[0] as [Buffer];
      expect(reportData.subarray(32).equals(nonce)).toBe(true);
      expect(result.reportData.endsWith(nonce.toString('hex'))).toBe(true);
    });

    it.each(['getMlKemPublicKey', 'getKeyManifest'] as const)(
      'refuses to attest when %s returns nothing',
      async (method) => {
        mockKeyDerivationService[method].mockReturnValue(null);

        await expect(service.getAttestation()).rejects.toThrow(
          ServiceUnavailableException,
        );
        expect(
          mockTeePlatformService.generateAttestationReport,
        ).not.toHaveBeenCalled();
      },
    );

    it('should propagate errors from TEE platform service', async () => {
      mockTeePlatformService.generateAttestationReport.mockRejectedValue(
        new Error('TEE attestation generation failed'),
      );

      await expect(service.getAttestation()).rejects.toThrow(
        'TEE attestation generation failed',
      );
    });
  });
});
