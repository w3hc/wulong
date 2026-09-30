import * as http from 'http';
import * as https from 'https';
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { SanitizedLogger } from './logging/sanitized-logger';
import { TeeExceptionFilter } from './filters/tee-exception.filter';
import { TeeTlsService } from './tls/tee-tls.service';
import {
  configureCors,
  configureResponseHeaders,
  configureTrustProxy,
  parseCorsOrigins,
} from './http/http-config';

async function bootstrap() {
  const isProd = process.env.NODE_ENV === 'production';

  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: isProd ? new SanitizedLogger() : undefined,
  });

  // Security headers - protects against common web vulnerabilities
  app.use(helmet());

  configureCors(app, parseCorsOrigins(process.env.CORS_ORIGINS));
  configureResponseHeaders(app);

  // Global validation pipe - validates all incoming requests
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Strip properties that don't have decorators
      forbidNonWhitelisted: true, // Throw error if non-whitelisted properties exist
      transform: true, // Transform payloads to DTO instances
    }),
  );

  // Global exception filter - sanitizes all error responses
  app.useGlobalFilters(new TeeExceptionFilter());

  // Swagger UI outside production only: public API docs make probing easier
  if (!isProd) {
    const config = new DocumentBuilder()
      .setTitle('Wulong API')
      .setDescription('API documentation for Wulong')
      .setVersion('0.3.0')
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('', app, document);
  }

  // Graceful shutdown handling
  app.enableShutdownHooks();

  // Runs onModuleInit, which is where TeeTlsService obtains the certificate
  await app.init();

  // TLS terminates in the enclave; its certificate is only known once the app
  // is initialized, so the server is created here rather than by NestFactory
  const tlsOptions = app.get(TeeTlsService).getServerOptions();
  if (!tlsOptions && !isProd) {
    throw new Error(
      'No TLS certificate: create secrets/tls.key and secrets/tls.cert, see README.md',
    );
  }
  if (!tlsOptions && process.env.ALLOW_TLS_OUTSIDE_ENCLAVE !== 'true') {
    throw new Error('Refusing to serve plain HTTP without in-enclave TLS');
  }

  configureTrustProxy(app, tlsOptions !== null);

  const port = 3000;
  const handler = app.getHttpAdapter().getInstance();
  const server = tlsOptions
    ? https.createServer(tlsOptions, handler)
    : http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(port, resolve));

  // Log startup only in dev mode (production logger filters this out)
  const protocol = tlsOptions ? 'https' : 'http';
  console.log(`Application is running on: ${protocol}://localhost:${port}`);
}

void bootstrap();
