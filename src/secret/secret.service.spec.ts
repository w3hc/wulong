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
import { TeeTlsService } from '../tls/tee-tls.service';
import { RelayerService } from '../relayer/relayer.service';
import { MlKemEncryptionService } from '../encryption/mlkem-encryption.service';
import { createHash, createHmac } from 'crypto';
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
    rm: jest.fn(),
  },
}));

// Mock ethers module
jest.mock('ethers', () => ({
  ...jest.requireActual<typeof import('ethers')>('ethers'),
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
  const relayerAddress = '0x602cA51341d6d1ff32b2ce8442c5e807A527CA17';
  const relayer = new Uint8Array(Buffer.from(relayerAddress.slice(2), 'hex'));

  const keyManifest = {
    manifest: {
      appId: '0x1111111111111111111111111111111111111111',
      mlkemPublicKeyHash: '0x' + '22'.repeat(32),
      relayer: relayerAddress,
      epoch: 1,
    },
    signature: '0x' + '33'.repeat(65),
  };

  const mockKeyDerivationService = {
    getMlKemPublicKey: jest.fn(),
    getIdentityPublicKey: jest.fn(),
    getKeyManifest: jest.fn(),
    getIdentitySignatureChain: jest.fn(),
    getRelayerAddress: jest.fn(),
    getRelayerSignatureChain: jest.fn(),
    getRelayerPublicKey: jest.fn(),
    macChestEntry: jest.fn(),
  };

  const macKey = Buffer.alloc(32, 0x42);
  const macChestEntry = (data: Uint8Array) =>
    createHmac('sha256', macKey).update(data).digest();

  // Pins the MAC encoding: changing it makes every stored entry unreadable
  const seal = (
    slot: string,
    encryptedPayload: ReturnType<typeof createMockEncryptedPayload>,
    publicAddresses: string[],
  ) => ({
    version: 2,
    encryptedPayload,
    publicAddresses,
    mac: macChestEntry(
      Buffer.from(
        JSON.stringify([
          'wulong-chest-entry',
          2,
          slot,
          1,
          encryptedPayload.recipients.map((r) => [r.publicKey, r.ciphertext]),
          encryptedPayload.encryptedData,
          encryptedPayload.iv,
          encryptedPayload.authTag,
          publicAddresses,
        ]),
      ),
    ).toString('hex'),
  });

  const mockTeeTlsService = {
    getLeafCertificateDer: jest.fn(),
  };

  const mockRelayerService = {
    isEnabled: jest.fn(),
    getLatestAnchor: jest.fn(),
    anchorChest: jest.fn<Promise<string>, [string, bigint]>(),
  };

  const serverPublicKey = Buffer.alloc(1568, 'a').toString('base64');

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
          publicKey: publicKey || serverPublicKey,
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
        {
          provide: TeeTlsService,
          useValue: mockTeeTlsService,
        },
        {
          provide: RelayerService,
          useValue: mockRelayerService,
        },
      ],
    }).compile();

    service = module.get<SecretService>(SecretService);

    // Reset mocks
    jest.clearAllMocks();
    mockMlKemEncryptionService.getPublicKey.mockReturnValue(serverPublicKey);
    mockKeyDerivationService.macChestEntry.mockImplementation(macChestEntry);
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
      ).rejects.toThrow(
        new BadRequestException('Invalid Ethereum address in publicAddresses'),
      );

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
        mockKeyDerivationService as unknown as KeyDerivationService,
        mockTeeTlsService as unknown as TeeTlsService,
        mockRelayerService as unknown as RelayerService,
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
        mockKeyDerivationService as unknown as KeyDerivationService,
        mockTeeTlsService as unknown as TeeTlsService,
        mockRelayerService as unknown as RelayerService,
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
      ).rejects.toThrow('Invalid ML-KEM ciphertext size: expected 1600 bytes');
    });

    it('should accept a v2 payload with 1608-byte ciphertexts', async () => {
      const payload = {
        ...createMockEncryptedPayload(),
        version: 2 as const,
      };
      payload.recipients[0].ciphertext = Buffer.alloc(1608).toString('base64');

      await expect(
        service.store(
          payload,
          ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).resolves.toMatch(/^[0-9a-f]{64}$/);
    });

    it('should reject a v2 payload with v1-sized ciphertexts', async () => {
      const payload = {
        ...createMockEncryptedPayload(),
        version: 2 as const,
      };

      await expect(
        service.store(
          payload,
          ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow('Invalid ML-KEM ciphertext size: expected 1608 bytes');
    });

    it('should reject an unsupported payload version', async () => {
      const payload = { ...createMockEncryptedPayload(), version: 3 };

      await expect(
        service.store(
          payload as unknown as ReturnType<typeof createMockEncryptedPayload>,
          ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow('Unsupported encrypted payload version');
    });

    it('should reject a recipient public key that is not 1568 bytes', async () => {
      const payload = createMockEncryptedPayload();
      payload.recipients.push({
        publicKey: Buffer.alloc(32).toString('base64'),
        ciphertext: payload.recipients[0].ciphertext,
      });

      await expect(
        service.store(
          payload,
          ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow('Invalid ML-KEM public key size: expected 1568 bytes');
      expect(fs.promises.writeFile).not.toHaveBeenCalled();
    });

    it('should reject a payload the server is not a recipient of', async () => {
      const payload = createMockEncryptedPayload(
        Buffer.alloc(1568, 'b').toString('base64'),
      );

      await expect(
        service.store(
          payload,
          ['0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c'],
          '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c',
        ),
      ).rejects.toThrow(
        new BadRequestException(
          'Invalid encrypted payload: the server must be one of the recipients',
        ),
      );
      expect(fs.promises.writeFile).not.toHaveBeenCalled();
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
      const mockData = {
        [testSlot]: seal(testSlot, createMockEncryptedPayload(), [
          testAddress.toLowerCase(),
        ]),
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
      ).rejects.toThrow(new NotFoundException('Slot not found'));
    });

    it('should throw the same NotFoundException if caller is not an owner', async () => {
      const unauthorizedAddress = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

      await expect(
        service.access(testSlot, unauthorizedAddress),
      ).rejects.toThrow(new NotFoundException('Slot not found'));
    });

    it('should throw NotFoundException for a slot named after an Object property', async () => {
      await expect(service.access('__proto__', testAddress)).rejects.toThrow(
        new NotFoundException('Slot not found'),
      );
    });

    describe('entry authentication', () => {
      const attacker = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8';
      const chestWith = (entries: Record<string, unknown>) =>
        jest
          .spyOn(fs.promises, 'readFile')
          .mockResolvedValue(JSON.stringify(entries));

      it('rejects an address appended to the access list on disk', async () => {
        const entry = seal(testSlot, createMockEncryptedPayload(), [
          testAddress,
        ]);
        entry.publicAddresses.push(attacker);
        chestWith({ [testSlot]: entry });

        await expect(service.access(testSlot, attacker)).rejects.toThrow(
          new NotFoundException('Slot not found'),
        );
        await expect(service.access(testSlot, testAddress)).rejects.toThrow(
          new NotFoundException('Slot not found'),
        );
        expect(
          mockMlKemEncryptionService.decryptMultiRecipient,
        ).not.toHaveBeenCalled();
      });

      it('rejects a payload swapped on disk', async () => {
        const entry = seal(testSlot, createMockEncryptedPayload(), [
          testAddress,
        ]);
        entry.encryptedPayload.encryptedData = Buffer.alloc(100, 'x').toString(
          'base64',
        );
        chestWith({ [testSlot]: entry });

        await expect(service.access(testSlot, testAddress)).rejects.toThrow(
          new NotFoundException('Slot not found'),
        );
      });

      it('rejects an entry moved to another slot', async () => {
        const otherSlot = 'b'.repeat(64);
        chestWith({
          [otherSlot]: seal(testSlot, createMockEncryptedPayload(), [
            testAddress,
          ]),
        });

        await expect(service.access(otherSlot, testAddress)).rejects.toThrow(
          new NotFoundException('Slot not found'),
        );
      });

      it('rejects a legacy entry without a version or MAC', async () => {
        chestWith({
          [testSlot]: {
            encryptedPayload: createMockEncryptedPayload(),
            publicAddresses: [testAddress],
          },
        });

        await expect(service.access(testSlot, testAddress)).rejects.toThrow(
          new NotFoundException('Slot not found'),
        );
      });

      it('rejects a malformed entry as not found rather than failing', async () => {
        chestWith({
          [testSlot]: { version: 2, mac: 'ab', publicAddresses: [testAddress] },
        });

        await expect(service.access(testSlot, testAddress)).rejects.toThrow(
          new NotFoundException('Slot not found'),
        );
      });

      it('accesses what store sealed', async () => {
        jest.spyOn(fs, 'existsSync').mockReturnValue(false);
        const payload = { ...createMockEncryptedPayload(), extra: 'dropped' };
        const slot = await service.store(payload, [testAddress], testAddress);
        const written = JSON.parse(
          (
            (fs.promises.writeFile as jest.Mock).mock.calls[0] as [
              string,
              string,
            ]
          )[1],
        ) as Record<string, { version: number; encryptedPayload: object }>;

        expect(written[slot].version).toBe(2);
        expect(written[slot].encryptedPayload).not.toHaveProperty('extra');

        jest.spyOn(fs, 'existsSync').mockReturnValue(true);
        chestWith(written);
        await expect(service.access(slot, testAddress)).resolves.toBe(
          testSecret,
        );
      });
    });

    it('should allow access if caller is one of multiple owners', async () => {
      const address1 = '0xbfbaa5a59e3b6c06aff9c975092b8705f804fa1c';
      const address2 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

      const mockData = {
        [testSlot]: seal(testSlot, createMockEncryptedPayload(), [
          address1.toLowerCase(),
          address2.toLowerCase(),
        ]),
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
          throw new Error('Unsupported state or unable to authenticate data');
        },
      );

      await expect(service.access(testSlot, testAddress)).rejects.toThrow(
        new BadRequestException('Failed to decrypt secret'),
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
      measurements: {
        mrtd: 'aa',
        rtmr0: 'bb',
        rtmr1: 'cc',
        rtmr2: 'dd',
        rtmr3: 'ee',
      },
      eventLog: '[]',
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
      mockKeyDerivationService.getRelayerAddress.mockReturnValue(
        relayerAddress,
      );
      mockKeyDerivationService.getRelayerPublicKey.mockReturnValue(
        new Uint8Array(65).fill(0x04),
      );
      mockKeyDerivationService.getRelayerSignatureChain.mockReturnValue([
        new Uint8Array([0xdd]),
      ]);
      mockTeePlatformService.generateAttestationReport.mockResolvedValue(
        mockAttestation,
      );
    });

    it('quotes the report_data committing to the keys', async () => {
      const expected = buildReportData({
        mlkemPublicKey,
        relayer,
        identityPublicKey,
      });

      const result = await service.getAttestation();

      expect(
        mockTeePlatformService.generateAttestationReport,
      ).toHaveBeenCalledWith(expected);
      expect(result).toEqual({
        ...mockAttestation,
        mlkemPublicKey: Buffer.from(mlkemPublicKey).toString('base64'),
        identityPublicKey: `0x${Buffer.from(identityPublicKey).toString('hex')}`,
        relayerAddress,
        relayerPublicKey: '0x' + '04'.repeat(65),
        tlsCertificate: undefined,
        reportData: `0x${expected.toString('hex')}`,
        keyManifest,
        identitySignatureChain: ['0xaabb', '0xcc'],
        relayerSignatureChain: ['0xdd'],
      });
    });

    it('commits report_data to the TLS certificate served in the enclave', async () => {
      const tlsCertificateDer = new Uint8Array([0x30, 0x82, 0x01]);
      mockTeeTlsService.getLeafCertificateDer.mockReturnValue(
        tlsCertificateDer,
      );
      const expected = buildReportData({
        mlkemPublicKey,
        relayer,
        identityPublicKey,
        tlsCertificateDer,
      });

      const result = await service.getAttestation();

      expect(
        mockTeePlatformService.generateAttestationReport,
      ).toHaveBeenCalledWith(expected);
      expect(result.reportData).toBe(`0x${expected.toString('hex')}`);
      expect(result.tlsCertificate).toBe(
        Buffer.from(tlsCertificateDer).toString('base64'),
      );
    });

    it('places the client nonce in report_data', async () => {
      const nonce = Buffer.alloc(32, 0x7f);

      const result = await service.getAttestation(nonce);

      const [reportData] = mockTeePlatformService.generateAttestationReport.mock
        .calls[0] as [Buffer];
      expect(reportData.subarray(32).equals(nonce)).toBe(true);
      expect(result.reportData.endsWith(nonce.toString('hex'))).toBe(true);
    });

    it.each([
      'getMlKemPublicKey',
      'getRelayerAddress',
      'getRelayerPublicKey',
      'getKeyManifest',
    ] as const)('refuses to attest when %s returns nothing', async (method) => {
      mockKeyDerivationService[method].mockReturnValue(null);

      await expect(service.getAttestation()).rejects.toThrow(
        ServiceUnavailableException,
      );
      expect(
        mockTeePlatformService.generateAttestationReport,
      ).not.toHaveBeenCalled();
    });

    it('should propagate errors from TEE platform service', async () => {
      mockTeePlatformService.generateAttestationReport.mockRejectedValue(
        new Error('TEE attestation generation failed'),
      );

      await expect(service.getAttestation()).rejects.toThrow(
        'TEE attestation generation failed',
      );
    });
  });

  describe('anchoring', () => {
    const chestPath = path.join(process.cwd(), 'chest.json');
    const pendingPath = `${chestPath}.pending`;
    const chest = Buffer.from('{"a":1}');
    const pending = Buffer.from('{"a":1,"b":2}');
    const rootOf = (bytes: Buffer) =>
      `0x${createHash('sha256').update(bytes).digest('hex')}`;
    const files = (contents: Record<string, Buffer>) =>
      (fs.promises.readFile as jest.Mock).mockImplementation((file: string) =>
        file in contents
          ? Promise.resolve(contents[file])
          : Promise.reject(
              Object.assign(new Error('ENOENT'), { code: 'ENOENT' }),
            ),
      );

    describe('at boot', () => {
      it('warns about entries that fail authentication', async () => {
        const warn = jest.spyOn(service['logger'], 'warn').mockImplementation();
        const slot = 'a'.repeat(64);
        mockRelayerService.getLatestAnchor.mockResolvedValue(null);
        mockMlKemEncryptionService.isAvailable.mockReturnValue(true);
        (fs.existsSync as jest.Mock).mockReturnValue(true);
        (fs.promises.readFile as jest.Mock).mockResolvedValue(
          JSON.stringify({
            [slot]: seal(slot, createMockEncryptedPayload(), ['0x01']),
            ['b'.repeat(64)]: { publicAddresses: [] },
          }),
        );

        await service.onModuleInit();

        expect(warn).toHaveBeenCalledWith(
          expect.stringMatching(/^1 chest entries fail authentication/),
        );
      });

      it('does nothing when the relayer does not anchor', async () => {
        mockRelayerService.getLatestAnchor.mockResolvedValue(null);

        await service.onModuleInit();

        expect(fs.promises.readFile).not.toHaveBeenCalled();
      });

      it('accepts the anchored chest and drops a stale pending write', async () => {
        files({ [chestPath]: chest, [pendingPath]: pending });
        mockRelayerService.getLatestAnchor.mockResolvedValue({
          root: rootOf(chest),
          seq: 3n,
        });

        await service.onModuleInit();

        expect(fs.promises.rm).toHaveBeenCalledWith(pendingPath, {
          force: true,
        });
        expect(fs.promises.rename).not.toHaveBeenCalled();
      });

      it('promotes a pending write that was anchored before a crash', async () => {
        files({ [chestPath]: chest, [pendingPath]: pending });
        mockRelayerService.getLatestAnchor.mockResolvedValue({
          root: rootOf(pending),
          seq: 4n,
        });

        await service.onModuleInit();

        expect(fs.promises.rename).toHaveBeenCalledWith(pendingPath, chestPath);
      });

      it.each([
        ['rolled back', { [chestPath]: chest }],
        ['deleted', {}],
      ])('refuses a chest that was %s', async (_, contents) => {
        files(contents);
        mockRelayerService.getLatestAnchor.mockResolvedValue({
          root: rootOf(pending),
          seq: 4n,
        });

        await expect(service.onModuleInit()).rejects.toThrow(
          'rolled back or altered',
        );
      });

      it('anchors a chest that was never anchored', async () => {
        files({ [chestPath]: chest });
        mockRelayerService.getLatestAnchor.mockResolvedValue({
          root: '0x' + '00'.repeat(32),
          seq: 0n,
        });

        await service.onModuleInit();

        expect(mockRelayerService.anchorChest).toHaveBeenCalledWith(
          rootOf(chest),
          1n,
        );
      });

      it('anchors nothing when there is no chest yet', async () => {
        files({});
        mockRelayerService.getLatestAnchor.mockResolvedValue({
          root: '0x' + '00'.repeat(32),
          seq: 0n,
        });

        await service.onModuleInit();

        expect(mockRelayerService.anchorChest).not.toHaveBeenCalled();
      });
    });

    describe('on store', () => {
      const payload = () => createMockEncryptedPayload();
      const owner = '0x' + '12'.repeat(20);
      let written: string;
      const order: string[] = [];

      beforeEach(async () => {
        order.length = 0;
        mockMlKemEncryptionService.isAvailable.mockReturnValue(true);
        (ethers.isAddress as unknown as jest.Mock).mockReturnValue(true);
        (fs.existsSync as jest.Mock).mockReturnValue(false);
        (fs.promises.writeFile as jest.Mock).mockImplementation(
          (file: string, data: string) => {
            order.push(`write ${file}`);
            written = data;
            return Promise.resolve();
          },
        );
        (fs.promises.rename as jest.Mock).mockImplementation(() => {
          order.push('rename');
          return Promise.resolve();
        });
        mockRelayerService.isEnabled.mockReturnValue(true);
        mockRelayerService.anchorChest.mockImplementation(() => {
          order.push('anchor');
          return Promise.resolve('0xhash');
        });
        files({ [chestPath]: chest });
        mockRelayerService.getLatestAnchor.mockResolvedValue({
          root: rootOf(chest),
          seq: 3n,
        });
        await service.onModuleInit();
      });

      it('anchors the pending chest before it replaces the chest', async () => {
        await service.store(payload(), [owner], owner);

        expect(order).toEqual([`write ${pendingPath}`, 'anchor', 'rename']);
        expect(mockRelayerService.anchorChest).toHaveBeenCalledWith(
          rootOf(Buffer.from(written)),
          4n,
        );
        expect(fs.promises.rename).toHaveBeenCalledWith(pendingPath, chestPath);
      });

      it('increments the seq on every write', async () => {
        await service.store(payload(), [owner], owner);
        await service.store(payload(), [owner], owner);

        expect(
          mockRelayerService.anchorChest.mock.calls.map((c) => c[1]),
        ).toEqual([4n, 5n]);
      });

      it('keeps the chest and fails the store when anchoring fails', async () => {
        mockRelayerService.anchorChest.mockRejectedValue(new Error('reverted'));

        await expect(
          service.store(payload() as never, [owner], owner),
        ).rejects.toThrow(ServiceUnavailableException);
        expect(fs.promises.rename).not.toHaveBeenCalled();
        expect(fs.promises.rm).toHaveBeenCalledWith(pendingPath, {
          force: true,
        });
      });

      it('commits a write whose transaction was included despite the error', async () => {
        mockRelayerService.anchorChest.mockImplementation(() => {
          mockRelayerService.getLatestAnchor.mockResolvedValue({
            root: rootOf(Buffer.from(written)),
            seq: 4n,
          });
          return Promise.reject(new Error('timeout'));
        });

        await service.store(payload(), [owner], owner);

        expect(fs.promises.rename).toHaveBeenCalledWith(pendingPath, chestPath);
      });

      it('resyncs the seq after a failure', async () => {
        mockRelayerService.anchorChest.mockRejectedValueOnce(
          new Error('reverted'),
        );
        mockRelayerService.getLatestAnchor.mockResolvedValue({
          root: '0x' + 'ff'.repeat(32),
          seq: 7n,
        });

        await expect(
          service.store(payload() as never, [owner], owner),
        ).rejects.toThrow(ServiceUnavailableException);
        await service.store(payload(), [owner], owner);

        expect(mockRelayerService.anchorChest).toHaveBeenLastCalledWith(
          expect.any(String),
          8n,
        );
      });
    });
  });
});
