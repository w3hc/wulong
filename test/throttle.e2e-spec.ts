import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';

describe('Rate limiting (e2e)', () => {
  let app: INestApplication<App>;
  const limit = 3;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.KMS_URL = 'http://localhost:3001';
    process.env.THROTTLE_LIMIT = String(limit);

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('returns 429 once the limit is reached', async () => {
    for (let i = 0; i < limit; i++) {
      await request(app.getHttpServer()).get('/health').expect(200);
    }

    await request(app.getHttpServer()).get('/health').expect(429);
  });

  it('counts each route separately', async () => {
    const address = '0x0000000000000000000000000000000000000001';
    for (let i = 0; i < limit; i++) {
      await request(app.getHttpServer())
        .post('/auth/nonce')
        .send({ address })
        .expect(201);
    }

    await request(app.getHttpServer())
      .post('/auth/nonce')
      .send({ address })
      .expect(429);
  });
});
