import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

// Request headers that fingerprint a client or reveal where it came from
export const IDENTIFYING_HEADERS = [
  'user-agent',
  'referer',
  'referrer',
  'origin',
  'x-real-ip',
  'x-client-ip',
  'cf-connecting-ip',
  'true-client-ip',
  'via',
  'accept-language',
  'accept-encoding',
  'accept-charset',
  'dnt',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
  'sec-fetch-user',
];

/**
 * Deletes IDENTIFYING_HEADERS from every request before any route code sees
 * it, so no handler or log line can record them.
 *
 * Ported from zk-api, which also deletes X-Forwarded-For and reports every
 * client as 0.0.0.0. Here the rate limiter keys on req.ip, which Express
 * derives from X-Forwarded-For behind a TLS-terminating proxy, so both are
 * kept: blanking them would put all clients in one rate-limit bucket. CORS is
 * applied before module middleware, so deleting Origin does not affect it.
 */
@Injectable()
export class RequestSanitizerMiddleware implements NestMiddleware {
  use(req: Request, _res: Response, next: NextFunction): void {
    for (const header of IDENTIFYING_HEADERS) {
      delete req.headers[header];
    }
    next();
  }
}
