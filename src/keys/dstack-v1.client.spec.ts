import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { getAddress } from 'ethers';
import { DstackV1Client } from './dstack-v1.client';

describe('DstackV1Client', () => {
  let server: http.Server;
  let tmpDir: string;
  let requests: { url?: string; body: unknown }[];
  let reply: { status: number; body: string };

  const listen = (target: string | number) =>
    new Promise<void>((resolve) => server.listen(target, resolve));

  beforeEach(() => {
    requests = [];
    reply = {
      status: 200,
      body: JSON.stringify({
        key: 'aa'.repeat(32),
        public_key: '02' + 'bb'.repeat(32),
        signature_chain: ['cc'.repeat(65), 'dd'.repeat(65)],
      }),
    };
    server = http.createServer((req, res) => {
      let data = '';
      req.on('data', (chunk) => (data += chunk));
      req.on('end', () => {
        requests.push({ url: req.url, body: data ? JSON.parse(data) : null });
        res.writeHead(reply.status, { 'Content-Type': 'application/json' });
        res.end(reply.body);
      });
    });
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dstack-'));
  });

  afterEach(async () => {
    delete process.env.DSTACK_SIMULATOR_ENDPOINT;
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('reads the app id from Info as a checksummed address', async () => {
    const socket = path.join(tmpDir, 'dstack.sock');
    await listen(socket);
    process.env.DSTACK_SIMULATOR_ENDPOINT = socket;
    reply.body = JSON.stringify({
      app_id: 'ab'.repeat(20),
      instance_id: '',
      app_cert: '',
      tcb_info: '{}',
      app_name: 'wulong',
    });

    const appId = await new DstackV1Client().getAppId();

    expect(appId).toBe(getAddress('0x' + 'ab'.repeat(20)));
    expect(requests[0].url).toMatch(/Info$/);
  });

  it('calls /v1/GetKey over a unix socket and decodes the response', async () => {
    const socket = path.join(tmpDir, 'dstack.sock');
    await listen(socket);
    process.env.DSTACK_SIMULATOR_ENDPOINT = socket;

    const client = new DstackV1Client();
    const result = await client.getKey('wulong/test/v1', 'ed25519');

    expect(requests).toEqual([
      {
        url: '/v1/GetKey',
        body: { domain: 'wulong/test/v1', algorithm: 'ed25519' },
      },
    ]);
    expect(Buffer.from(result.key).toString('hex')).toBe('aa'.repeat(32));
    expect(result.publicKey).toHaveLength(33);
    expect(result.signatureChain).toHaveLength(2);
    expect(client.isSimulator()).toBe(true);
  });

  it('calls /v1/GetKey over http when the endpoint is a URL', async () => {
    await listen(0);
    const { port } = server.address() as AddressInfo;
    process.env.DSTACK_SIMULATOR_ENDPOINT = `http://127.0.0.1:${port}`;

    await new DstackV1Client().getKey('d', 'secp256k1');

    expect(requests[0].url).toBe('/v1/GetKey');
  });

  it('uses the dstack socket when no simulator is configured', () => {
    expect(new DstackV1Client().isSimulator()).toBe(false);
  });

  it('rejects when the agent has no v1 surface', async () => {
    const socket = path.join(tmpDir, 'dstack.sock');
    await listen(socket);
    process.env.DSTACK_SIMULATOR_ENDPOINT = socket;
    reply = { status: 404, body: 'Not Found' };

    await expect(new DstackV1Client().getKey('d', 'ed25519')).rejects.toThrow(
      '/v1/GetKey failed (404)',
    );
  });

  it('rejects malformed hex instead of truncating it', async () => {
    const socket = path.join(tmpDir, 'dstack.sock');
    await listen(socket);
    process.env.DSTACK_SIMULATOR_ENDPOINT = socket;
    reply = {
      status: 200,
      body: JSON.stringify({
        key: 'aazz',
        public_key: '02',
        signature_chain: [],
      }),
    };

    await expect(new DstackV1Client().getKey('d', 'ed25519')).rejects.toThrow(
      'malformed key',
    );
  });

  it('rejects when the socket is unreachable', async () => {
    process.env.DSTACK_SIMULATOR_ENDPOINT = path.join(tmpDir, 'missing.sock');

    await expect(new DstackV1Client().getKey('d', 'ed25519')).rejects.toThrow();
  });
});
