import { AbiCoder, Interface, Provider, Transaction, Wallet } from 'ethers';
import { KeyDerivationService } from '../keys/key-derivation.service';
import { ANCHOR_ABI, RelayerService } from './relayer.service';

const ANCHOR = '0x' + '77'.repeat(20);
const wallet = new Wallet('0x' + '43'.repeat(32));
const iface = new Interface(ANCHOR_ABI);
const coder = AbiCoder.defaultAbiCoder();
const root = '0x' + 'ab'.repeat(32);

const keys = {
  getRelayerAddress: jest.fn(() => wallet.address as string | null),
  signRelayerTransaction: jest.fn((tx: Record<string, unknown>) => {
    const unsigned = Transaction.from(tx);
    unsigned.signature = wallet.signingKey.sign(unsigned.unsignedHash);
    return unsigned.serialized;
  }),
};

const createProvider = () => {
  const state = { onChainRelayer: wallet.address, status: 1 };
  const mocks = {
    call: jest.fn(({ data }: { data: string }) => {
      const selector = data.slice(0, 10);
      if (selector === iface.getFunction('relayer')!.selector) {
        return Promise.resolve(
          coder.encode(['address'], [state.onChainRelayer]),
        );
      }
      return Promise.resolve(
        coder.encode(['bytes32', 'uint64', 'uint64'], [root, 4n, 1000n]),
      );
    }),
    getNetwork: jest.fn(() => Promise.resolve({ chainId: 8453n })),
    getBalance: jest.fn(() => Promise.resolve(10n ** 15n)),
    getTransactionCount: jest.fn(() => Promise.resolve(3)),
    getFeeData: jest.fn(() =>
      Promise.resolve({ maxFeePerGas: 100n, maxPriorityFeePerGas: 1n }),
    ),
    estimateGas: jest.fn(() => Promise.resolve(50_000n)),
    broadcastTransaction: jest.fn((signed: string) =>
      Promise.resolve({
        hash: Transaction.from(signed).hash,
        wait: () =>
          Promise.resolve({
            hash: Transaction.from(signed).hash,
            status: state.status,
          }),
      }),
    ),
  };
  return Object.assign(state, mocks);
};

describe('RelayerService', () => {
  const originalEnv = { ...process.env };
  let provider: ReturnType<typeof createProvider>;

  const create = async (withProvider = true) => {
    const service = new RelayerService(
      keys as unknown as KeyDerivationService,
      withProvider ? (provider as unknown as Provider) : null,
    );
    await service.onModuleInit();
    return service;
  };

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.WULONG_ANCHOR_ADDRESS = ANCHOR;
    process.env.NODE_ENV = 'test';
    delete process.env.RELAYER_MAX_BALANCE_WEI;
    provider = createProvider();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe('startup', () => {
    it('anchors when the contract trusts this relayer', async () => {
      const service = await create();

      expect(service.isEnabled()).toBe(true);
      expect(service.getStatus()).toEqual({
        address: wallet.address,
        anchor: ANCHOR,
        balanceWei: (10n ** 15n).toString(),
        maxBalanceWei: (10n ** 16n).toString(),
      });
    });

    it('is disabled without an anchor address', async () => {
      delete process.env.WULONG_ANCHOR_ADDRESS;

      const service = await create();

      expect(service.isEnabled()).toBe(false);
      expect(await service.getLatestAnchor()).toBeNull();
      expect(provider.call).not.toHaveBeenCalled();
    });

    it('requires an RPC with an anchor address', async () => {
      await expect(create(false)).rejects.toThrow('BASE_RPC_URL');
    });

    it('fails in production when the contract trusts another relayer', async () => {
      process.env.NODE_ENV = 'production';
      provider.onChainRelayer = '0x' + '99'.repeat(20);

      await expect(create()).rejects.toThrow('trusts relayer');
    });

    it('disables anchoring outside production when the contract trusts another relayer', async () => {
      provider.onChainRelayer = '0x' + '99'.repeat(20);

      const service = await create();

      expect(service.isEnabled()).toBe(false);
      await expect(service.anchorChest(root, 5n)).rejects.toThrow('disabled');
    });

    it('is disabled when the relayer key is not derived', async () => {
      keys.getRelayerAddress.mockReturnValueOnce(null);

      const service = await create();

      expect(service.isEnabled()).toBe(false);
    });
  });

  describe('anchorChest', () => {
    it('sends only an anchor call to the anchor contract', async () => {
      const service = await create();

      const hash = await service.anchorChest(root, 5n);

      const [signed] = provider.broadcastTransaction.mock.calls[0];
      const tx = Transaction.from(signed);
      expect(tx.hash).toBe(hash);
      expect(tx.from).toBe(wallet.address);
      expect(tx.to).toBe(ANCHOR);
      expect(tx.chainId).toBe(8453n);
      expect(tx.nonce).toBe(3);
      expect(tx.value).toBe(0n);
      expect(tx.gasLimit).toBe(60_000n);
      expect(iface.decodeFunctionData('anchor', tx.data)).toEqual([root, 5n]);
    });

    it('rejects when the transaction reverts', async () => {
      const service = await create();
      provider.status = 0;

      await expect(service.anchorChest(root, 5n)).rejects.toThrow('failed');
    });

    it('sends one transaction at a time', async () => {
      const service = await create();
      let inFlight = 0;
      let maxInFlight = 0;
      provider.getTransactionCount.mockImplementation(async () => {
        maxInFlight = Math.max(maxInFlight, ++inFlight);
        await new Promise((resolve) => setImmediate(resolve));
        inFlight--;
        return 3;
      });

      await Promise.all([
        service.anchorChest(root, 5n),
        service.anchorChest(root, 6n),
      ]);

      expect(maxInFlight).toBe(1);
      expect(provider.broadcastTransaction).toHaveBeenCalledTimes(2);
    });

    it('keeps sending after a failed transaction', async () => {
      const service = await create();
      provider.estimateGas.mockRejectedValueOnce(new Error('revert'));

      await expect(service.anchorChest(root, 5n)).rejects.toThrow('revert');
      await expect(service.anchorChest(root, 5n)).resolves.toMatch(/^0x/);
    });

    it('refreshes the balance after sending', async () => {
      process.env.RELAYER_MAX_BALANCE_WEI = '1';
      const service = await create();
      provider.getBalance.mockResolvedValueOnce(42n);

      await service.anchorChest(root, 5n);

      expect(service.getStatus().balanceWei).toBe('42');
      expect(service.getStatus().maxBalanceWei).toBe('1');
    });
  });

  it('reads the latest anchor', async () => {
    const service = await create();

    expect(await service.getLatestAnchor()).toEqual({ root, seq: 4n });
  });
});
