import { Controller, Get, ServiceUnavailableException } from '@nestjs/common';
import { KeyDerivationService } from '../keys/key-derivation.service';
import { RelayerService } from '../relayer/relayer.service';

/**
 * Health check endpoint for monitoring and load balancers.
 * Returns minimal information to avoid leaking internal state.
 */
@Controller('health')
export class HealthController {
  constructor(
    private readonly keys: KeyDerivationService,
    private readonly relayer: RelayerService,
  ) {}

  /**
   * Basic health check endpoint.
   * @returns Health status object
   */
  @Get()
  check() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Readiness probe - ready only once the keys are derived, since every
   * store and access needs them.
   * @returns Readiness status
   * @throws ServiceUnavailableException (503) until the keys are derived
   */
  @Get('ready')
  ready() {
    if (!this.keys.isAvailable()) {
      throw new ServiceUnavailableException('Not ready');
    }
    return {
      status: 'ready',
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * The relayer wallet, for topping it up: its address, the anchor contract
   * and the last balance read. All public on chain.
   * @returns Relayer status
   */
  @Get('relayer')
  relayerStatus() {
    return {
      ...this.relayer.getStatus(),
      anchoring: this.relayer.isEnabled(),
    };
  }

  /**
   * Liveness probe - indicates if the service is alive.
   * @returns Liveness status
   */
  @Get('live')
  live() {
    return {
      status: 'alive',
      timestamp: new Date().toISOString(),
    };
  }
}
