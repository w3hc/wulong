import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AttestationModule } from './attestation/attestation.module';
import { HealthController } from './health/health.controller';
import { validateEnvironment } from './config/env.validation';
import { SecretModule } from './secret/secret.module';
import { AuthModule } from './auth/auth.module';
import { TlsModule } from './tls/tls.module';
import { KeysModule } from './keys/keys.module';
import { TimingProtectionInterceptor } from './interceptors/timing-protection.interceptor';
import { MetadataSanitizerInterceptor } from './interceptors/metadata-sanitizer.interceptor';
import { RequestSanitizerMiddleware } from './middleware/request-sanitizer.middleware';

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
    KeysModule,
    SecretModule,
    TlsModule,
  ],
  controllers: [AppController, HealthController],
  providers: [
    AppService,
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_INTERCEPTOR, useClass: TimingProtectionInterceptor },
    { provide: APP_INTERCEPTOR, useClass: MetadataSanitizerInterceptor },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestSanitizerMiddleware).forRoutes('*');
  }
}
