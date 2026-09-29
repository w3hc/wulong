import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { SecretsService } from './config/secrets.service';
import { AttestationModule } from './attestation/attestation.module';
import { HealthController } from './health/health.controller';
import { validateEnvironment } from './config/env.validation';
import { SecretModule } from './secret/secret.module';
import { AuthModule } from './auth/auth.module';
import { TlsModule } from './tls/tls.module';

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
    AttestationModule,
    AuthModule,
    SecretModule,
    TlsModule,
  ],
  controllers: [AppController, HealthController],
  providers: [
    AppService,
    SecretsService,
    { provide: APP_GUARD, useClass: ThrottlerGuard },
  ],
  exports: [SecretsService],
})
export class AppModule {}
