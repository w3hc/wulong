import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Interface, Provider, getAddress } from 'ethers';
import { KeyDerivationService } from '../keys/key-derivation.service';

export const RELAYER_PROVIDER = Symbol('RELAYER_PROVIDER');

export const ANCHOR_ABI = [
  'function anchor(bytes32 root, uint64 seq)',
  'function latest() view returns (bytes32 root, uint64 seq, uint64 anchoredAt)',
  'function relayer() view returns (address)',
];

const DEFAULT_MAX_BALANCE_WEI = 10n ** 16n;
const CONFIRMATION_TIMEOUT_MS = 60_000;

export interface ChestAnchor {
  root: string;
  seq: bigint;
}

export interface RelayerStatus {
  address: string | null;
  anchor: string | null;
  balanceWei: string | null;
  maxBalanceWei: string;
}

/**
 * Sends Wulong's on-chain transactions from the enclave-derived relayer
 * wallet. Its only action is anchoring the chest: there is no method, and no
 * endpoint, that sends or signs anything else.
 *
 * The wallet should hold only the gas it needs, topped up from outside: a
 * future malicious registered build could spend it. A balance above
 * RELAYER_MAX_BALANCE_WEI is logged.
 *
 * Nonces come from the pending count and sends are queued, so a single
 * instance must send. See docs/KEY_DERIVATION.md#the-relayer-wallet.
 */
@Injectable()
export class RelayerService implements OnModuleInit {
  private readonly logger = new Logger(RelayerService.name);
  private readonly anchorAddress: string | null;
  private readonly maxBalance: bigint;
  private readonly iface = new Interface(ANCHOR_ABI);
  private chainId: bigint | null = null;
  private balance: bigint | null = null;
  private enabled = false;
  private sendQueue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly keys: KeyDerivationService,
    @Inject(RELAYER_PROVIDER) private readonly provider: Provider | null,
  ) {
    const anchor = process.env.WULONG_ANCHOR_ADDRESS;
    this.anchorAddress = anchor ? getAddress(anchor) : null;
    this.maxBalance = BigInt(
      process.env.RELAYER_MAX_BALANCE_WEI ?? DEFAULT_MAX_BALANCE_WEI,
    );
  }

  async onModuleInit(): Promise<void> {
    const production = process.env.NODE_ENV === 'production';

    if (!this.anchorAddress) {
      this.logger.warn(
        'WULONG_ANCHOR_ADDRESS is not set: the chest is not anchored on chain and can be rolled back',
      );
      return;
    }
    if (!this.provider) {
      throw new Error('BASE_RPC_URL must be set with WULONG_ANCHOR_ADDRESS');
    }
    const relayer = this.keys.getRelayerAddress();
    if (!relayer) {
      this.logger.warn('Relayer key not derived, anchoring disabled');
      return;
    }

    const [onChainRelayer] = await this.read('relayer');
    if (getAddress(onChainRelayer as string) !== relayer) {
      const message = `WulongAnchor ${this.anchorAddress} trusts relayer ${onChainRelayer as string}, not ${relayer}`;
      if (production) {
        throw new Error(message);
      }
      this.logger.warn(`${message}, anchoring disabled`);
      return;
    }

    this.chainId = (await this.provider.getNetwork()).chainId;
    this.enabled = true;
    await this.checkBalance();
    this.logger.log(
      `Relayer ${relayer} anchors to ${this.anchorAddress} on chain ${this.chainId}`,
    );
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  /** The latest commitment the relayer wrote, or null when not anchoring. */
  async getLatestAnchor(): Promise<ChestAnchor | null> {
    if (!this.enabled) {
      return null;
    }
    const [root, seq] = await this.read('latest');
    return { root: root as string, seq: seq as bigint };
  }

  /**
   * Anchors the chest commitment after its `seq`-th write and waits for the
   * transaction to be included.
   * @param root 32-byte commitment to the chest, hex
   * @param seq Greater than the anchored seq
   * @returns The transaction hash
   * @throws Error if anchoring is disabled, or the transaction fails
   */
  anchorChest(root: string, seq: bigint): Promise<string> {
    const send = this.sendQueue.then(() => this.send(root, seq));
    this.sendQueue = send.catch(() => undefined);
    return send;
  }

  getStatus(): RelayerStatus {
    return {
      address: this.keys.getRelayerAddress(),
      anchor: this.anchorAddress,
      balanceWei: this.balance?.toString() ?? null,
      maxBalanceWei: this.maxBalance.toString(),
    };
  }

  private async send(root: string, seq: bigint): Promise<string> {
    const from = this.keys.getRelayerAddress();
    if (!this.enabled || !this.provider || !this.anchorAddress || !from) {
      throw new Error('Anchoring is disabled');
    }
    const to = this.anchorAddress;
    const data = this.iface.encodeFunctionData('anchor', [root, seq]);
    const [nonce, fees, gas] = await Promise.all([
      this.provider.getTransactionCount(from, 'pending'),
      this.provider.getFeeData(),
      this.provider.estimateGas({ from, to, data }),
    ]);
    if (fees.maxFeePerGas === null || fees.maxPriorityFeePerGas === null) {
      throw new Error('The RPC returned no EIP-1559 fees');
    }

    const signed = this.keys.signRelayerTransaction({
      type: 2,
      chainId: this.chainId,
      nonce,
      to,
      data,
      gasLimit: (gas * 12n) / 10n,
      maxFeePerGas: fees.maxFeePerGas,
      maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
    });
    const response = await this.provider.broadcastTransaction(signed);
    const receipt = await response.wait(1, CONFIRMATION_TIMEOUT_MS);
    if (!receipt || receipt.status !== 1) {
      throw new Error(`Anchor transaction ${response.hash} failed`);
    }

    await this.checkBalance().catch((error: Error) =>
      this.logger.warn(`Relayer balance check failed: ${error.message}`),
    );
    return receipt.hash;
  }

  private async checkBalance(): Promise<void> {
    const address = this.keys.getRelayerAddress();
    if (!this.provider || !address) {
      return;
    }
    this.balance = await this.provider.getBalance(address);
    if (this.balance > this.maxBalance) {
      this.logger.warn(
        `Relayer balance ${this.balance} wei is above the ${this.maxBalance} wei cap: a malicious registered build could spend it`,
      );
    } else if (this.balance === 0n) {
      this.logger.warn(`Relayer ${address} has no gas: top it up`);
    }
  }

  private async read(fn: 'relayer' | 'latest') {
    const result = await this.provider!.call({
      to: this.anchorAddress!,
      data: this.iface.encodeFunctionData(fn),
    });
    return this.iface.decodeFunctionResult(fn, result);
  }
}
