import { Test } from '@nestjs/testing';
import { AppModule } from './app.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { TeePlatformService } from './attestation/tee-platform.service';
import { HealthController } from './health/health.controller';
import { AuthController } from './auth/auth.controller';
import { SiweService } from './auth/siwe.service';

describe('AppModule', () => {
  it('should compile the module', async () => {
    const module = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    expect(module).toBeDefined();
  });

  it('should have all controllers registered', async () => {
    const module = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    const appController = module.get<AppController>(AppController);
    const healthController = module.get<HealthController>(HealthController);
    const authController = module.get<AuthController>(AuthController);

    expect(appController).toBeDefined();
    expect(healthController).toBeDefined();
    expect(authController).toBeDefined();
  });

  it('should have all providers registered', async () => {
    const module = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    const appService = module.get<AppService>(AppService);
    const teePlatformService =
      module.get<TeePlatformService>(TeePlatformService);
    const siweService = module.get<SiweService>(SiweService);

    expect(appService).toBeDefined();
    expect(teePlatformService).toBeDefined();
    expect(siweService).toBeDefined();
  });
});
