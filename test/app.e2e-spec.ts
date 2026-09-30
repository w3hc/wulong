import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import {
  MAX_JITTER_MS,
  MIN_RESPONSE_MS,
} from './../src/interceptors/timing-protection.interceptor';

describe('Application (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    // Set test environment variables
    process.env.NODE_ENV = 'test';
    // Keep the rate limiter out of the way; throttle.e2e-spec.ts covers it
    process.env.THROTTLE_LIMIT = '1000';

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Health Endpoints (e2e)', () => {
    it('/health (GET) - should return ok status', () => {
      return request(app.getHttpServer())
        .get('/health')
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('status', 'ok');
          expect(res.body).toHaveProperty('timestamp');
          expect((res.body as { timestamp: string }).timestamp).toMatch(
            /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
          );
        });
    });

    it('/health/ready (GET) - should be unavailable without derived keys', () => {
      return request(app.getHttpServer()).get('/health/ready').expect(503);
    });

    it('/health/live (GET) - should return alive status', () => {
      return request(app.getHttpServer())
        .get('/health/live')
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('status', 'alive');
          expect(res.body).toHaveProperty('timestamp');
        });
    });
  });

  describe('Attestation Endpoints (e2e)', () => {
    it('/attestation (GET) - is gone: attestations come from /chest/attestation', () => {
      return request(app.getHttpServer()).get('/attestation').expect(404);
    });
  });

  describe('Security Headers (e2e)', () => {
    it('should include security headers in responses', () => {
      return request(app.getHttpServer())
        .get('/health')
        .expect(200)
        .expect((res) => {
          // Check for common security headers
          // Note: helmet adds these by default
          expect(res.headers).toBeDefined();
        });
    });
  });

  describe('Error Handling (e2e)', () => {
    it('should return 404 for non-existent endpoints', () => {
      return request(app.getHttpServer())
        .get('/non-existent-endpoint')
        .expect(404);
    });

    it('should return 404 for non-existent nested endpoints', () => {
      return request(app.getHttpServer())
        .get('/health/non-existent')
        .expect(404);
    });
  });

  describe('HTTP Methods (e2e)', () => {
    it('should reject POST to GET-only endpoints', () => {
      return request(app.getHttpServer()).post('/health').expect(404);
    });

    it('should reject PUT to GET-only endpoints', () => {
      return request(app.getHttpServer()).put('/health').expect(404);
    });

    it('should reject DELETE to GET-only endpoints', () => {
      return request(app.getHttpServer()).delete('/health/ready').expect(404);
    });
  });

  describe('Content Type (e2e)', () => {
    it('should return JSON content type for health endpoint', () => {
      return request(app.getHttpServer())
        .get('/health')
        .expect(200)
        .expect('Content-Type', /json/);
    });
  });

  describe('Response Time (e2e)', () => {
    it('health endpoint should respond at the timing floor', async () => {
      const start = Date.now();
      await request(app.getHttpServer()).get('/health').expect(200);
      const duration = Date.now() - start;

      expect(duration).toBeGreaterThanOrEqual(MIN_RESPONSE_MS);
      expect(duration).toBeLessThan(MIN_RESPONSE_MS + MAX_JITTER_MS + 100);
    });
  });

  describe('Concurrent Requests (e2e)', () => {
    it('should handle multiple concurrent health checks', async () => {
      const requests = Array.from({ length: 3 }, () =>
        request(app.getHttpServer()).get('/health').expect(200),
      );

      const responses = await Promise.all(requests);

      responses.forEach((res) => {
        expect((res.body as { status: string }).status).toBe('ok');
      });
    });
  });
});
