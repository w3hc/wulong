import {
  CallHandler,
  ExecutionContext,
  NotFoundException,
} from '@nestjs/common';
import { Observable, map, of, throwError, timer } from 'rxjs';
import {
  MAX_JITTER_MS,
  MIN_RESPONSE_MS,
  TimingProtectionInterceptor,
} from './timing-protection.interceptor';

describe('TimingProtectionInterceptor', () => {
  const context = {} as ExecutionContext;
  let interceptor: TimingProtectionInterceptor;

  // Subscribes and records when the observable settles, and how
  const track = (observable: Observable<unknown>) => {
    const outcome: { settledAt?: number; value?: unknown; error?: unknown } =
      {};
    observable.subscribe({
      next: (value) => {
        outcome.value = value;
        outcome.settledAt = Date.now();
      },
      error: (error: unknown) => {
        outcome.error = error;
        outcome.settledAt = Date.now();
      },
    });
    return outcome;
  };

  const handlerOf = (observable: Observable<unknown>): CallHandler => ({
    handle: () => observable,
  });

  beforeEach(() => {
    jest.useFakeTimers({ now: 0 });
    interceptor = new TimingProtectionInterceptor();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('holds a successful response until the minimum time has passed', () => {
    const outcome = track(
      interceptor.intercept(context, handlerOf(of('secret'))),
    );

    jest.advanceTimersByTime(MIN_RESPONSE_MS - 1);
    expect(outcome.settledAt).toBeUndefined();

    jest.advanceTimersByTime(MAX_JITTER_MS + 1);
    expect(outcome.value).toBe('secret');
    expect(outcome.settledAt).toBeGreaterThanOrEqual(MIN_RESPONSE_MS);
    expect(outcome.settledAt).toBeLessThanOrEqual(
      MIN_RESPONSE_MS + MAX_JITTER_MS,
    );
  });

  it('holds an error response for the same time', () => {
    const notFound = new NotFoundException('Slot not found');
    const outcome = track(
      interceptor.intercept(context, handlerOf(throwError(() => notFound))),
    );

    jest.advanceTimersByTime(MIN_RESPONSE_MS - 1);
    expect(outcome.settledAt).toBeUndefined();

    jest.advanceTimersByTime(MAX_JITTER_MS + 1);
    expect(outcome.error).toBe(notFound);
    expect(outcome.settledAt).toBeGreaterThanOrEqual(MIN_RESPONSE_MS);
  });

  it('adds no delay to a handler slower than the minimum', () => {
    const slow = MIN_RESPONSE_MS + MAX_JITTER_MS + 50;
    const outcome = track(
      interceptor.intercept(
        context,
        handlerOf(timer(slow).pipe(map(() => 'late'))),
      ),
    );

    jest.advanceTimersByTime(slow);
    expect(outcome.value).toBe('late');
    expect(outcome.settledAt).toBe(slow);
  });

  it('varies the response time', () => {
    const settledAt = new Set<number>();
    for (let i = 0; i < 20; i++) {
      jest.setSystemTime(0);
      const outcome = track(interceptor.intercept(context, handlerOf(of(i))));
      jest.advanceTimersByTime(MIN_RESPONSE_MS + MAX_JITTER_MS);
      settledAt.add(outcome.settledAt!);
    }

    expect(settledAt.size).toBeGreaterThan(1);
  });
});
