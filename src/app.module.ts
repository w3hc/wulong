import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { SecretsService } from './config/secrets.service';
import { AttestationController } from './attestation/attestation.controller';
import { TeePlatformService } from './attestation/tee-platform.service';
import { HealthController } from './health/health.controller';
import { validateEnvironment } from './config/env.validation';
import { SecretModule } from './secret/secret.module';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    // Environment variable validation
    ConfigModule.forRoot({
      isGlobal: true,
      validate: validateEnvironment,
    }),
    // Rate limiting to prevent DoS attacks
    ThrottlerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => [
        {
          ttl: Number(config.get('THROTTLE_TTL') ?? 60000),
          limit: Number(config.get('THROTTLE_LIMIT') ?? 10),
        },
      ],
    }),
    AuthModule,
    SecretModule,
  ],
  controllers: [AppController, AttestationController, HealthController],
  providers: [
    AppService,
    SecretsService,
    TeePlatformService,
    { provide: APP_GUARD, useClass: ThrottlerGuard },
  ],
  exports: [SecretsService, TeePlatformService],
})
export class AppModule {}
