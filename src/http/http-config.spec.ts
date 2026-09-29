import { Controller, Get, INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { App } from 'supertest/types';
import { configureCors, parseCorsOrigins } from './http-config';

@Controller()
class PingController {
  @Get('ping')
  ping() {
    return 'pong';
  }
}

async function createApp(
  setup: (app: INestApplication) => void,
): Promise<INestApplication<App>> {
  const module = await Test.createTestingModule({
    controllers: [PingController],
  }).compile();
  const app = module.createNestApplication<INestApplication<App>>();
  setup(app);
  await app.init();
  return app;
}

describe('parseCorsOrigins', () => {
  it('returns no origin when unset or empty', () => {
    expect(parseCorsOrigins(undefined)).toEqual([]);
    expect(parseCorsOrigins('')).toEqual([]);
    expect(parseCorsOrigins(' , ')).toEqual([]);
  });

  it('splits and trims a comma-separated list', () => {
    expect(
      parseCorsOrigins('https://app.example.com, http://localhost:5173'),
    ).toEqual(['https://app.example.com', 'http://localhost:5173']);
  });

  it.each(['*', 'app.example.com', 'https://app.example.com/', 'https://a/b'])(
    'rejects %s',
    (origin) => {
      expect(() => parseCorsOrigins(origin)).toThrow(/CORS_ORIGINS/);
    },
  );
});

describe('configureCors', () => {
  let app: INestApplication<App>;
  const allowed = 'https://app.example.com';

  beforeAll(async () => {
    app = await createApp((a) => configureCors(a, [allowed]));
  });

  afterAll(async () => {
    await app.close();
  });

  it('allows a listed origin without credentials', async () => {
    const res = await request(app.getHttpServer())
      .get('/ping')
      .set('Origin', allowed)
      .expect(200);

    expect(res.headers['access-control-allow-origin']).toBe(allowed);
    expect(res.headers['access-control-allow-credentials']).toBeUndefined();
  });

  it('does not allow an unlisted origin', async () => {
    const res = await request(app.getHttpServer())
      .get('/ping')
      .set('Origin', 'https://evil.example.com')
      .expect(200);

    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('allows the SIWE headers on preflight', async () => {
    const res = await request(app.getHttpServer())
      .options('/ping')
      .set('Origin', allowed)
      .set('Access-Control-Request-Method', 'GET')
      .set('Access-Control-Request-Headers', 'x-siwe-message,x-siwe-signature')
      .expect(204);

    expect(res.headers['access-control-allow-headers']).toMatch(
      /X-SIWE-Message/,
    );
  });

  it('allows no origin when the list is empty', async () => {
    const closed = await createApp((a) => configureCors(a, []));
    const res = await request(closed.getHttpServer())
      .get('/ping')
      .set('Origin', allowed)
      .expect(200);
    await closed.close();

    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});
