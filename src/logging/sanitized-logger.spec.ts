import { SanitizedLogger } from './sanitized-logger';

describe('SanitizedLogger', () => {
  let logger: SanitizedLogger;
  let stdoutSpy: jest.SpyInstance;

  beforeEach(() => {
    logger = new SanitizedLogger();
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation();
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
  });

  describe('log', () => {
    it('should log messages from safe contexts', () => {
      logger.log('Application started', 'NestFactory');

      expect(stdoutSpy).toHaveBeenCalledWith(
        '[LOG] NestFactory: Application started\n',
      );
    });

    it('should log messages from InstanceLoader context', () => {
      logger.log('Loading modules', 'InstanceLoader');

      expect(stdoutSpy).toHaveBeenCalledWith(
        '[LOG] InstanceLoader: Loading modules\n',
      );
    });

    it('should log messages from RoutesResolver context', () => {
      logger.log('Mapping routes', 'RoutesResolver');

      expect(stdoutSpy).toHaveBeenCalledWith(
        '[LOG] RoutesResolver: Mapping routes\n',
      );
    });

    it('should not log messages from unsafe contexts', () => {
      logger.log('Sensitive data', 'UserService');

      expect(stdoutSpy).not.toHaveBeenCalled();
    });

    it('should not log when context is undefined', () => {
      logger.log('Some message');

      expect(stdoutSpy).not.toHaveBeenCalled();
    });
  });

  describe('error', () => {
    it('should log error messages without stack traces', () => {
      logger.error('Something went wrong', 'stack trace here', 'AppService');

      expect(stdoutSpy).toHaveBeenCalledWith(
        '[ERR] AppService: Something went wrong\n',
      );
    });

    it('should use default context when not provided', () => {
      logger.error('Error occurred');

      expect(stdoutSpy).toHaveBeenCalledWith('[ERR] App: Error occurred\n');
    });

    it('should only log first line of multiline error messages', () => {
      logger.error('Error line 1\nError line 2\nError line 3', '', 'Service');

      expect(stdoutSpy).toHaveBeenCalledWith('[ERR] Service: Error line 1\n');
    });

    it('should handle undefined error message', () => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      logger.error(undefined as any, '', 'Service');

      expect(stdoutSpy).toHaveBeenCalledWith('[ERR] Service: undefined\n');
    });
  });

  describe('redaction', () => {
    // Assembled at runtime so no key-shaped literal is committed
    const label = ['PRIVATE', 'KEY'].join(' ');
    const pem = [
      `-----BEGIN ${label}-----`,
      'not-a-key',
      `-----END ${label}-----`,
    ].join('\n');
    const hexKey = `0x${'ab'.repeat(32)}`;

    it('should redact a known secret value from a logged error', () => {
      const secretLogger = new SanitizedLogger({
        RELAYER_API_TOKEN: 'hunter2-hunter2',
      });

      secretLogger.error(
        'Upstream rejected token hunter2-hunter2',
        '',
        'Relayer',
      );

      expect(stdoutSpy).toHaveBeenCalledWith(
        '[ERR] Relayer: Upstream rejected token [REDACTED]\n',
      );
    });

    it('should redact a PEM private key before keeping the first line', () => {
      logger.error(`Bad key ${pem}`, '', 'TeeTlsService');

      expect(stdoutSpy).toHaveBeenCalledWith(
        '[ERR] TeeTlsService: Bad key [REDACTED]\n',
      );
    });

    it('should redact hex keys', () => {
      logger.error(`Cannot parse ${hexKey}`, '', 'Keys');

      expect(stdoutSpy).toHaveBeenCalledWith(
        '[ERR] Keys: Cannot parse [REDACTED]\n',
      );
    });

    it('should redact long base64 values in logs and warnings', () => {
      const b64 = Buffer.alloc(48, 7).toString('base64');

      logger.log(`key ${b64}`, 'NestFactory');
      logger.warn(`key ${b64}`, 'NestFactory');

      expect(stdoutSpy).toHaveBeenCalledWith(
        '[LOG] NestFactory: key [REDACTED]\n',
      );
      expect(stdoutSpy).toHaveBeenCalledWith(
        '[WARN] NestFactory: key [REDACTED]\n',
      );
    });

    it('should keep addresses and short values', () => {
      const address = '0x' + '1'.repeat(40);
      const quiet = new SanitizedLogger({ SHORT_KEY: 'abc' });

      quiet.error(`abc from ${address}`, '', 'Auth');

      expect(stdoutSpy).toHaveBeenCalledWith(
        `[ERR] Auth: abc from ${address}\n`,
      );
    });
  });

  describe('warn', () => {
    it('should warn messages from safe contexts', () => {
      logger.warn('Deprecation warning', 'NestApplication');

      expect(stdoutSpy).toHaveBeenCalledWith(
        '[WARN] NestApplication: Deprecation warning\n',
      );
    });

    it('should warn messages from RouterExplorer context', () => {
      logger.warn('Route warning', 'RouterExplorer');

      expect(stdoutSpy).toHaveBeenCalledWith(
        '[WARN] RouterExplorer: Route warning\n',
      );
    });

    it('should not warn messages from unsafe contexts', () => {
      logger.warn('Unsafe warning', 'CustomService');

      expect(stdoutSpy).not.toHaveBeenCalled();
    });

    it('should not warn when context is undefined', () => {
      logger.warn('Warning message');

      expect(stdoutSpy).not.toHaveBeenCalled();
    });
  });

  describe('debug', () => {
    it('should suppress all debug messages', () => {
      logger.debug('Debug message', 'NestFactory');

      expect(stdoutSpy).not.toHaveBeenCalled();
    });
  });

  describe('verbose', () => {
    it('should suppress all verbose messages', () => {
      logger.verbose('Verbose message', 'NestFactory');

      expect(stdoutSpy).not.toHaveBeenCalled();
    });
  });
});
