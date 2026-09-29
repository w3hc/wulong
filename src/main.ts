import * as fs from 'fs';
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { SanitizedLogger } from './logging/sanitized-logger';
import { TeeExceptionFilter } from './filters/tee-exception.filter';

async function bootstrap() {
  const isProd = process.env.NODE_ENV === 'production';

  // HTTPS only in dev with self-signed certs
  // Production uses HTTP behind Phala's TLS termination proxy
  const httpsOptions = !isProd
    ? {
        key: fs.readFileSync('./secrets/tls.key'),
        cert: fs.readFileSync('./secrets/tls.cert'),
      }
    : undefined;

  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    httpsOptions,
    logger: isProd ? new SanitizedLogger() : undefined,
  });

  // Rate limiting keys on the client IP, which Phala's proxy forwards
  // in X-Forwarded-For; trust that single hop only
  if (isProd) {
    app.set('trust proxy', 1);
  }

  // Security headers - protects against common web vulnerabilities
  app.use(helmet());

  // CORS configuration - restrict to trusted origins in production
  app.enableCors({
    origin: isProd ? false : '*', // Disable CORS in production by default
    credentials: true,
  });

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

  // Swagger API documentation setup
  const config = new DocumentBuilder()
    .setTitle('Wulong API')
    .setDescription('API documentation for Wulong')
    .setVersion('0.1.0')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('', app, document);

  // Graceful shutdown handling
  app.enableShutdownHooks();

  const port = 3000;
  await app.listen(port);

  // Log startup only in dev mode (production logger filters this out)
  const protocol = isProd ? 'http' : 'https';
  console.log(`Application is running on: ${protocol}://localhost:${port}`);
}

void bootstrap();
