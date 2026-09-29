import {
  CallHandler,
  ExecutionContext,
  NotFoundException,
} from '@nestjs/common';
import { lastValueFrom, of, throwError } from 'rxjs';
import {
  MetadataSanitizerInterceptor,
  REVEALING_HEADERS,
} from './metadata-sanitizer.interceptor';

describe('MetadataSanitizerInterceptor', () => {
  let interceptor: MetadataSanitizerInterceptor;
  let headers: Map<string, string>;
  let context: ExecutionContext;

  const handlerOf = (result: ReturnType<CallHandler['handle']>) => ({
    handle: () => result,
  });

  beforeEach(() => {
    interceptor = new MetadataSanitizerInterceptor();
    headers = new Map(REVEALING_HEADERS.map((name) => [name, 'leak']));
    headers.set('content-type', 'application/json');
    const response = {
      removeHeader: (name: string) => headers.delete(name.toLowerCase()),
      setHeader: (name: string, value: string) =>
        headers.set(name.toLowerCase(), value),
    };
    context = {
      switchToHttp: () => ({ getResponse: () => response }),
    } as unknown as ExecutionContext;
  });

  const expectSanitized = () => {
    for (const name of REVEALING_HEADERS) {
      expect(headers.has(name)).toBe(false);
    }
    expect(headers.get('cache-control')).toBe('no-store');
    expect(headers.get('pragma')).toBe('no-cache');
    expect(headers.get('expires')).toBe('0');
    expect(headers.get('content-type')).toBe('application/json');
  };

  it('sanitizes a successful response and passes its body through', async () => {
    await expect(
      lastValueFrom(interceptor.intercept(context, handlerOf(of('body')))),
    ).resolves.toBe('body');
    expectSanitized();
  });

  it('sanitizes an error response and rethrows the error', async () => {
    const notFound = new NotFoundException('Slot not found');
    await expect(
      lastValueFrom(
        interceptor.intercept(context, handlerOf(throwError(() => notFound))),
      ),
    ).rejects.toBe(notFound);
    expectSanitized();
  });
});
