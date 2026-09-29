import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { randomInt } from 'crypto';
import {
  Observable,
  catchError,
  concatMap,
  map,
  of,
  throwError,
  timer,
} from 'rxjs';

export const MIN_RESPONSE_MS = 100;
export const MAX_JITTER_MS = 20;

/**
 * Holds every response, success or error, until at least MIN_RESPONSE_MS
 * plus a random jitter of up to MAX_JITTER_MS has passed since the handler
 * started, so "slot not found" and a successful lookup take the same time.
 *
 * Ported from zk-api, which only delayed successful responses. Handlers that
 * run longer than the floor are not padded further. Guards run before
 * interceptors, so SIWE and rate-limit rejections are not delayed.
 */
@Injectable()
export class TimingProtectionInterceptor implements NestInterceptor {
  intercept(
    _context: ExecutionContext,
    next: CallHandler,
  ): Observable<unknown> {
    const deadline =
      Date.now() + MIN_RESPONSE_MS + randomInt(MAX_JITTER_MS + 1);
    const untilDeadline = () => {
      const remaining = deadline - Date.now();
      return remaining > 0 ? timer(remaining) : of(0);
    };

    return next.handle().pipe(
      concatMap((data: unknown) => untilDeadline().pipe(map(() => data))),
      catchError((error: unknown) =>
        untilDeadline().pipe(concatMap(() => throwError(() => error))),
      ),
    );
  }
}
