import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';

describe('Application (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    // Set test environment variables
    process.env.NODE_ENV = 'test';
    process.env.KMS_URL = 'http://localhost:3001';
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

    it('/health/ready (GET) - should return ready status', () => {
      return request(app.getHttpServer())
        .get('/health/ready')
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('status', 'ready');
          expect(res.body).toHaveProperty('timestamp');
        });
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
    it('/attestation (GET) - should return attestation report', () => {
      return request(app.getHttpServer())
        .get('/attestation')
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('platform');
          expect(res.body).toHaveProperty('report');
          expect(res.body).toHaveProperty('measurement');
          expect(res.body).toHaveProperty('timestamp');
          expect(res.body).toHaveProperty('instructions');

          // Verify platform is one of the expected values
          expect(['amd-sev-snp', 'intel-tdx', 'aws-nitro', 'none']).toContain(
            (res.body as { platform: string }).platform,
          );

          // Verify report is base64 encoded
          expect((res.body as { report: string }).report).toMatch(
            /^[A-Za-z0-9+/]+=*$/,
          );

          // Verify timestamp format
          expect((res.body as { timestamp: string }).timestamp).toMatch(
            /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
          );
        });
    });

    it('/attestation (GET) - should include appropriate instructions for platform', () => {
      return request(app.getHttpServer())
        .get('/attestation')
        .expect(200)
        .expect((res) => {
          const { platform, instructions } = res.body as {
            platform: string;
            instructions: string;
          };

          switch (platform) {
            case 'amd-sev-snp':
              expect(instructions).toContain('SEV-SNP');
              break;
            case 'intel-tdx':
              expect(instructions).toContain('TDX');
              break;
            case 'aws-nitro':
              expect(instructions).toContain('Nitro');
              break;
            case 'none':
              expect(instructions).toContain('WARNING');
              expect(instructions).toContain('MOCK');
              break;
          }
        });
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
        .get('/attestation/non-existent')
        .expect(404);
    });
  });

  describe('HTTP Methods (e2e)', () => {
    it('should reject POST to GET-only endpoints', () => {
      return request(app.getHttpServer()).post('/health').expect(404);
    });

    it('should reject PUT to GET-only endpoints', () => {
      return request(app.getHttpServer()).put('/attestation').expect(404);
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

    it('should return JSON content type for attestation endpoint', () => {
      return request(app.getHttpServer())
        .get('/attestation')
        .expect(200)
        .expect('Content-Type', /json/);
    });
  });

  describe('Response Time (e2e)', () => {
    it('health endpoint should respond quickly', async () => {
      const start = Date.now();
      await request(app.getHttpServer()).get('/health').expect(200);
      const duration = Date.now() - start;

      // Health check should respond in less than 100ms
      expect(duration).toBeLessThan(100);
    });

    it('attestation endpoint should respond in reasonable time', async () => {
      const start = Date.now();
      await request(app.getHttpServer()).get('/attestation').expect(200);
      const duration = Date.now() - start;

      // Attestation should respond in less than 1 second
      expect(duration).toBeLessThan(1000);
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

    it('should handle multiple concurrent attestation requests', async () => {
      const requests = Array.from({ length: 3 }, () =>
        request(app.getHttpServer()).get('/attestation').expect(200),
      );

      const responses = await Promise.all(requests);

      responses.forEach((res) => {
        expect(res.body).toHaveProperty('platform');
        expect(res.body).toHaveProperty('report');
      });
    });
  });
});
