import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable, catchError, tap, throwError } from 'rxjs';

// Headers that reveal the server stack, correlate requests or describe caches
export const REVEALING_HEADERS = [
  'x-powered-by',
  'x-request-id',
  'x-correlation-id',
  'x-response-time',
  'x-runtime',
  'x-transaction-id',
  'x-trace-id',
  'x-span-id',
  'server',
  'etag',
  'last-modified',
  'via',
  'vary',
  'x-cache',
  'x-cache-hits',
  'x-served-by',
  'x-timer',
  'x-backend-server',
  'x-varnish',
  'age',
  'cf-ray',
  'cf-cache-status',
  'x-amz-cf-id',
  'x-amz-cf-pop',
  'x-azure-ref',
];

interface HeaderWriter {
  removeHeader(name: string): void;
  setHeader(name: string, value: string): void;
}

/**
 * Strips REVEALING_HEADERS from every response, success or error, and forbids
 * caching it anywhere.
 *
 * Ported from zk-api, which only sanitized successful responses. Express adds
 * ETag when it sends the body, after interceptors, so it is disabled in
 * configureResponseHeaders instead.
 */
@Injectable()
export class MetadataSanitizerInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const response = context.switchToHttp().getResponse<HeaderWriter>();
    const sanitize = () => {
      for (const header of REVEALING_HEADERS) {
        response.removeHeader(header);
      }
      response.setHeader('Cache-Control', 'no-store');
      response.setHeader('Pragma', 'no-cache');
      response.setHeader('Expires', '0');
    };

    return next.handle().pipe(
      tap(sanitize),
      catchError((error: unknown) => {
        sanitize();
        return throwError(() => error);
      }),
    );
  }
}
