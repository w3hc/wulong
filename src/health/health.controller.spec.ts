import { Test, TestingModule } from '@nestjs/testing';
import { ServiceUnavailableException } from '@nestjs/common';
import { HealthController } from './health.controller';
import { KeyDerivationService } from '../keys/key-derivation.service';
import { RelayerService } from '../relayer/relayer.service';

describe('HealthController', () => {
  let controller: HealthController;
  const keys = { isAvailable: jest.fn(() => true) };
  const status = {
    address: '0x' + '55'.repeat(20),
    anchor: '0x' + '77'.repeat(20),
    balanceWei: '42',
    maxBalanceWei: '100',
  };
  const relayer = {
    getStatus: jest.fn(() => status),
    isEnabled: jest.fn(() => true),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [HealthController],
      providers: [
        { provide: KeyDerivationService, useValue: keys },
        { provide: RelayerService, useValue: relayer },
      ],
    }).compile();

    controller = module.get<HealthController>(HealthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('check', () => {
    it('should return health status with ok status', () => {
      const result = controller.check();

      expect(result).toHaveProperty('status', 'ok');
      expect(result).toHaveProperty('timestamp');
      expect(result.timestamp).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      );
    });

    it('should return current timestamp', () => {
      const before = new Date();
      const result = controller.check();
      const after = new Date();

      const timestamp = new Date(result.timestamp);
      expect(timestamp.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(timestamp.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('ready', () => {
    it('should be unavailable until the keys are derived', () => {
      keys.isAvailable.mockReturnValueOnce(false);

      expect(() => controller.ready()).toThrow(ServiceUnavailableException);
    });

    it('should return readiness status', () => {
      const result = controller.ready();

      expect(result).toHaveProperty('status', 'ready');
      expect(result).toHaveProperty('timestamp');
      expect(result.timestamp).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      );
    });

    it('should return current timestamp', () => {
      const before = new Date();
      const result = controller.ready();
      const after = new Date();

      const timestamp = new Date(result.timestamp);
      expect(timestamp.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(timestamp.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('live', () => {
    it('should return liveness status', () => {
      const result = controller.live();

      expect(result).toHaveProperty('status', 'alive');
      expect(result).toHaveProperty('timestamp');
      expect(result.timestamp).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      );
    });

    it('should return current timestamp', () => {
      const before = new Date();
      const result = controller.live();
      const after = new Date();

      const timestamp = new Date(result.timestamp);
      expect(timestamp.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(timestamp.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('relayer', () => {
    it('reports the relayer wallet and whether it anchors', () => {
      expect(controller.relayerStatus()).toEqual({
        ...status,
        anchoring: true,
      });
    });
  });
});
