import {
  Controller,
  Get,
  MiddlewareConsumer,
  Module,
  NestModule,
  Req,
} from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { Request } from 'express';
import request from 'supertest';
import { configureCors, configureTrustProxy } from '../http/http-config';
import {
  IDENTIFYING_HEADERS,
  RequestSanitizerMiddleware,
} from './request-sanitizer.middleware';

@Controller()
class EchoController {
  @Get('echo')
  echo(@Req() req: Request) {
    return { headers: req.headers, ip: req.ip };
  }
}

@Module({ controllers: [EchoController] })
class EchoModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestSanitizerMiddleware).forRoutes('*');
  }
}

describe('RequestSanitizerMiddleware', () => {
  const origin = 'https://app.example.com';
  let app: NestExpressApplication;

  beforeAll(async () => {
    const module = await Test.createTestingModule({
      imports: [EchoModule],
    }).compile();
    app = module.createNestApplication<NestExpressApplication>();
    configureCors(app, [origin]);
    configureTrustProxy(app, false);
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  const echo = () => {
    const req = request(app.getHttpServer()).get('/echo');
    for (const name of IDENTIFYING_HEADERS) {
      req.set(name, name === 'origin' ? origin : 'identifying');
    }
    return req
      .set('x-siwe-message', 'kept')
      .set('x-forwarded-for', '203.0.113.7')
      .expect(200);
  };

  it('hides identifying headers from handlers', async () => {
    const res = await echo();
    const { headers } = res.body as { headers: Record<string, string> };

    for (const name of IDENTIFYING_HEADERS) {
      expect(headers[name]).toBeUndefined();
    }
    expect(headers['x-siwe-message']).toBe('kept');
  });

  it('keeps the client address the rate limiter keys on', async () => {
    const res = await echo();

    expect((res.body as { ip: string }).ip).toBe('203.0.113.7');
  });

  it('runs after CORS, which still sees Origin', async () => {
    const res = await echo();

    expect(res.headers['access-control-allow-origin']).toBe(origin);
  });
});
