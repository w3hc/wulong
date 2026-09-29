import { Controller, Get, Req } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { Request } from 'express';
import request from 'supertest';
import { App } from 'supertest/types';
import {
  configureCors,
  configureTrustProxy,
  parseCorsOrigins,
} from './http-config';

@Controller()
class PingController {
  @Get('ping')
  ping() {
    return 'pong';
  }

  @Get('ip')
  ip(@Req() req: Request) {
    return { ip: req.ip };
  }
}

async function createApp(
  setup: (app: NestExpressApplication) => void,
): Promise<NestExpressApplication> {
  const module = await Test.createTestingModule({
    controllers: [PingController],
  }).compile();
  const app = module.createNestApplication<NestExpressApplication>();
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
  let app: NestExpressApplication;
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

describe('configureTrustProxy', () => {
  const peer = /^(::ffff:)?127\.0\.0\.1$|^::1$/;

  async function ipSeen(tlsInEnclave: boolean, forwardedFor: string) {
    const app = await createApp((a) => configureTrustProxy(a, tlsInEnclave));
    const res = await request(app.getHttpServer() as App)
      .get('/ip')
      .set('X-Forwarded-For', forwardedFor)
      .expect(200);
    await app.close();
    return (res.body as { ip: string }).ip;
  }

  it('ignores X-Forwarded-For when TLS terminates in the enclave', async () => {
    expect(await ipSeen(true, '203.0.113.7')).toMatch(peer);
  });

  it('trusts the hop the proxy appended when TLS terminates outside', async () => {
    expect(await ipSeen(false, '203.0.113.7')).toBe('203.0.113.7');
  });

  it('ignores entries a client forged before the proxy hop', async () => {
    expect(await ipSeen(false, '198.51.100.1, 203.0.113.7')).toBe(
      '203.0.113.7',
    );
  });
});
