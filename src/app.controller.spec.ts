import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { SiweService } from './auth/siwe.service';
import { SiweGuard } from './auth/siwe.guard';
import { KeyDerivationService } from './keys/key-derivation.service';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';

describe('AppController', () => {
  let appController: AppController;
  let appService: AppService;
  let siweService: SiweService;
  let siweGuard: SiweGuard;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [
        AppService,
        SiweService,
        SiweGuard,
        {
          provide: KeyDerivationService,
          useValue: { isAvailable: () => false },
        },
      ],
    }).compile();

    appController = app.get<AppController>(AppController);
    appService = app.get<AppService>(AppService);
    siweService = app.get<SiweService>(SiweService);
    siweGuard = app.get<SiweGuard>(SiweGuard);
  });

  it('should be defined', () => {
    expect(appController).toBeDefined();
  });

  it('should have AppService injected', () => {
    expect(appService).toBeDefined();
  });

  it('should have SiweService injected', () => {
    expect(siweService).toBeDefined();
  });

  describe('hello endpoint', () => {
    it('should return greeting with authenticated address', () => {
      const mockRequest = {
        user: { address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' },
      };

      const result = appController.hello(mockRequest);

      expect(result.message).toBe('Hello, authenticated user!');
      expect(result.address).toBe('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266');
    });
  });

  describe('SiweGuard', () => {
    it('should throw UnauthorizedException when headers are missing', async () => {
      const mockContext = {
        switchToHttp: () => ({
          getRequest: () => ({
            headers: {},
          }),
        }),
      } as ExecutionContext;

      await expect(siweGuard.canActivate(mockContext)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException for invalid signature', async () => {
      const mockContext = {
        switchToHttp: () => ({
          getRequest: () => ({
            headers: {
              'x-siwe-message': 'invalid message',
              'x-siwe-signature': '0xinvalid',
            },
          }),
        }),
      } as ExecutionContext;

      await expect(siweGuard.canActivate(mockContext)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
