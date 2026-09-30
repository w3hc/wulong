# Phala Cloud Deployment Guide

This guide covers deploying the Wulong API to Phala Cloud's Trusted Execution Environment (TEE).

## Overview

Phala Cloud provides confidential computing infrastructure using Intel TDX (Trust Domain Extensions). Your application runs inside a hardware-isolated Trusted Execution Environment where:

- Secrets are encrypted end-to-end in your browser before being sent to the TEE
- Only your application inside the TEE can decrypt the secrets
- The cloud provider cannot access your secrets or application data
- Full attestation is available to verify the TEE environment

## Prerequisites

1. **Phala CLI installed**
   ```bash
   npm install -g @phala/cli
   ```

2. **A published release**: images are built in CI and pulled from `ghcr.io/w3hc/wulong`, which must be public (or Phala given registry credentials)

3. **Phala Cloud account** at https://cloud.phala.network

4. **Authentication**
   ```bash
   phala login
   ```

## Docker Image Requirements

### Architecture

Phala Cloud runs on **AMD64/x86_64** architecture. The [release workflow](../.github/workflows/release.yml) builds for `linux/amd64` and publishes the image digest in the release notes. Don't push images by hand: see [DOCKER.md](./DOCKER.md#releases).

### Image Configuration

The [Dockerfile](../Dockerfile) uses a multi-stage build:
1. **Builder stage**: Compiles TypeScript with all dependencies
2. **Production stage**: `dist` and production dependencies only, as the non-root `node` user, starts with `node dist/src/main.js`

Key points:
- Port 3000 serves HTTPS, terminated inside the enclave with a key and certificate issued by the dstack KMS ([src/tls/tee-tls.service.ts](../src/tls/tee-tls.service.ts))
- The gateway must run in TLS passthrough mode, see [Endpoint URL Format](#endpoint-url-format)
- Startup fails if the certificate cannot be obtained, unless `ALLOW_TLS_OUTSIDE_ENCLAVE=true` is added to the compose file, which serves plain HTTP behind the gateway, logs an error every minute, and changes the attested compose hash
- All secrets are loaded from environment variables injected by Phala

## Configuration Files

### docker-compose.yml

Environment variables must use the `${VAR}` syntax for Phala's encrypted secrets system:

```yaml
version: '3.8'

services:
  wulong:
    image: ghcr.io/w3hc/wulong@sha256:<digest>  # From the release notes
    ports:
      - "3000:3000"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock  # Required for TEE attestation
    environment:
      - NODE_ENV=${NODE_ENV}
      - CORS_ORIGINS=${CORS_ORIGINS}  # Browser UIs allowed to call the API
      - SIWE_DOMAIN=${SIWE_DOMAIN}  # UIs allowed to request a SIWE signature
      - TLS_ALT_NAMES=${TLS_ALT_NAMES}  # <APP_ID>-3000s.<CLUSTER>.phala.network
    restart: unless-stopped
```

**Important**:
- The image is pinned by digest: the attested compose hash then commits to the exact image, which a tag would not
- The `/var/run/dstack.sock` volume mount is **required**: attestation and key derivation go through it, and production refuses to start without `/v1/GetKey` (dstack ≥ 0.6.0 OS image)
- Deploy against the **on-chain KMS** (`DstackKms` on Base), not Phala Cloud's default KMS, so the app's allowed code versions are publicly governed; see [KEY_DERIVATION.md](./KEY_DERIVATION.md#what-no-one-can-know-rests-on)

### .env.prod

Create a local file with your production secrets (used during deployment):

```bash
NODE_ENV=production
SIWE_DOMAIN=app.example.com
TLS_ALT_NAMES=<APP_ID>-3000s.<CLUSTER>.phala.network
CORS_ORIGINS=https://app.example.com
```

Startup fails in production if `SIWE_DOMAIN` is missing, or `TLS_ALT_NAMES` unless `ALLOW_TLS_OUTSIDE_ENCLAVE=true`.

**Important**: Add `.env.prod` to [.gitignore](../.gitignore) to prevent committing secrets.

### ML-KEM Keys

There are no keys to generate or configure. Wulong derives its ML-KEM-1024 key pair and identity key at boot from the dstack KMS, through `/var/run/dstack.sock`. Every instance of the same app gets the same keys, and no one, including whoever deploys, ever handles them. Startup fails if `ADMIN_MLKEM_*`, any `*PRIVATE_KEY`, `*MNEMONIC` or `*SEED` variable, or `DSTACK_SIMULATOR_ENDPOINT` is set. See [KEY_DERIVATION.md](./KEY_DERIVATION.md).

## Deployment Process

### Initial Deployment

1. **Release the image**: push a `v*` tag, then pin the digest from the release notes in `docker-compose.yml` (see [DOCKER.md](./DOCKER.md#releases)).

2. **Deploy to Phala Cloud**:
   ```bash
   phala deploy --interactive
   ```

   Follow the prompts:
   - Docker Compose file: `docker-compose.yml`
   - Environment file: `.env.prod`
   - Select instance type (e.g., `tdx.small`)
   - Choose region
   - Configure storage

3. **Wait for deployment**:
   ```bash
   phala cvms list
   ```

### Updating Deployment

To update an existing deployment:

1. **Release a new image**: push a `v*` tag and pin the new digest in `docker-compose.yml`. The first upgrade from a pre-v0.2.0 image needs the volume handed to the `node` user, see [DOCKER.md](./DOCKER.md#upgrading-from-a-root-image).

2. **Update deployment** (a new digest changes the compose hash):
   ```bash
   phala deploy --interactive
   # Select existing CVM to update
   # Use docker-compose.yml and .env.prod when prompted
   ```

   **Important**: Simple `phala cvms restart` does NOT pull new images. You must use `phala deploy --interactive` to force image updates.

3. **Wait for deployment and verify**:
   ```bash
   phala cvms list
   # Wait for status to show "running"
   ```

## Useful Commands

### Instance Management

```bash
# List all CVMs
phala cvms list
phala apps

# Get CVM details
phala cvms get --interactive

# Restart CVM
phala cvms restart --interactive

# Stop CVM
phala cvms stop --interactive

# Start stopped CVM
phala cvms start --interactive

# Delete CVM
phala cvms delete --interactive
```

### Logs and Debugging

```bash
# View application logs
phala logs --interactive

# SSH into CVM
phala ssh --interactive

# Inside SSH session:
docker ps -a
docker logs dstack-wulong-1
docker inspect dstack-wulong-1
```

### SSH Key Management

```bash
# Add SSH key
phala ssh-keys add

# List SSH keys
phala ssh-keys list

# Remove SSH key
phala ssh-keys remove
```

### Instance Information

```bash
# View attestation
phala cvms attestation --interactive

# View runtime config
phala runtime-config --interactive
```

## Accessing Your Deployment

### Endpoint URL Format

Your application is accessible at:
```
https://<APP_ID>-<PORT>s.<CLUSTER>.phala.network
```

For example:
```
https://0214f0d80bd3b81d61c79653590789ac38979c43-3000s.dstack-pha-prod9.phala.network
```

The trailing `s` after the port puts the gateway in TLS passthrough mode: it forwards the encrypted stream and TLS terminates inside the enclave. Without it (`-3000`), the gateway terminates TLS itself, outside the enclave, and then speaks plain HTTP to a server that expects TLS. Set `TLS_ALT_NAMES` to this hostname so the certificate is issued for it.

The certificate is signed by the app's dstack KMS CA, not a public CA, so browsers and default HTTP clients reject it. Clients trust it by checking it against the attestation: `pnpm verify:attestation` does this.

### Finding Your Endpoint

1. **Via CLI**:
   ```bash
   phala cvms list
   # Shows APP_ID
   ```

2. **Via Phala Cloud UI**:
   - Go to instance details
   - Click "Network" tab
   - View "Ingress" URLs

### API Documentation

The Swagger UI is not served in production. Run the app locally to browse it, see [LOCAL_SETUP.md](./LOCAL_SETUP.md).

## Security Architecture

### Encrypted Secrets

Phala Cloud uses end-to-end encryption for secrets:

1. **Browser-side encryption**: When you deploy via UI or CLI, secrets are encrypted in your browser
2. **TEE-only decryption**: Only your application inside the TEE can decrypt the secrets
3. **No provider access**: Phala Cloud cannot access your decrypted secrets

### ML-KEM Encryption

The application uses ML-KEM-1024 (NIST FIPS 203) for quantum-resistant encryption:

- **Public key**: Exposed via `/chest/attestation` endpoint
- **Private key**: Derived inside the TEE from the dstack KMS at boot, never stored or exposed ([KEY_DERIVATION.md](./KEY_DERIVATION.md))
- **Security level**: NIST Level 5 (256-bit classical security)
- **Key sizes**: 1568 bytes (public), 3168 bytes (private)

See [docs/ENCRYPTION.md](./ENCRYPTION.md) for more details.

### Attestation

Fetch the attestation with a fresh 32-byte hex nonce:
```
https://<your-endpoint>.phala.network/chest/attestation?nonce=<64 hex chars>
```

Example response (abridged):
```json
{
  "platform": "intel-tdx",
  "report": "BAACAIEAAAAAAAAAk5pyM/ecTKmUCg2zlX8GB...",
  "measurements": {
    "mrtd": "c68518a0...",
    "rtmr0": "85e0855a...",
    "rtmr1": "9b43f9f3...",
    "rtmr2": "7cc2dadd...",
    "rtmr3": "d4e5f6a7..."
  },
  "eventLog": "[{\"imr\":0,\"event_type\":2147483659,...}]",
  "timestamp": "2026-09-29T06:23:34.980Z",
  "mlkemPublicKey": "6RNr8BvBcRe9ivVfuYkN40YCxgE...",
  "identityPublicKey": "0x04a1b2c3...",
  "tlsCertificate": "MIIBhDCCASmgAwIBAgIU...",
  "reportData": "0xab74ab29...",
  "keyManifest": { "manifest": { "appId": "0x...", "...": "..." }, "signature": "0x..." },
  "identitySignatureChain": ["0x...", "0x..."]
}
```

- `report`: the TDX v4 quote from the dstack guest agent
- `measurements`: MRTD and RTMR0–3 read from the quote. **RTMR3 identifies the app** (it extends the compose hash); MRTD and RTMR0–2 identify the dstack OS image. See [TEE_SETUP.md](./TEE_SETUP.md#measurements) for how to reproduce them.
- `eventLog`: replays RTMR0–3, including the `compose-hash` event
- `reportData` and the key fields: see [KEY_DERIVATION.md](./KEY_DERIVATION.md#verification)

Run `pnpm verify:attestation https://<your-endpoint>/chest/attestation` to check the key binding and the measurements ([scripts/README.md](../scripts/README.md)).

In production, `platform` is always `intel-tdx`: without `/var/run/dstack.sock`, or if the first quote fails, the app refuses to start.

## Troubleshooting

### "No logs available"

This usually means the container isn't starting. SSH into the CVM and check:

```bash
phala ssh --interactive
docker logs dstack-wulong-1
```

Common issues:
- **exec format error**: Wrong architecture (must be AMD64, not ARM64)
- **Missing secrets**: Environment variables not properly configured
- **Environment validation failed**: a setting required in production is missing, the message names it

### "exec format error"

The image was built for the wrong architecture. Released images are built for `linux/amd64`: check that `docker-compose.yml` pins a digest from a release.

### Container keeps restarting

Check logs via SSH:
```bash
phala ssh --interactive
docker logs dstack-wulong-1
```

Look for a startup error:
- `... must not be set in production`: remove key material or `DSTACK_SIMULATOR_ENDPOINT` from the env
- `Key derivation from dstack v1 GetKey failed`: the `dstack.sock` mount is missing, or the OS image predates dstack 0.6.0

### Container exits with "No dstack guest agent at /var/run/dstack.sock"

With `NODE_ENV=production`, the app refuses to run without the dstack socket. Check:

1. **The instance type is TEE-enabled**:
   ```bash
   phala cvms get --interactive
   ```
   Should show `tdx.small` or similar (not `standard`)

2. **The volume mount is configured**. Your `docker-compose.yml` must include:
   ```yaml
   volumes:
     - /var/run/dstack.sock:/var/run/dstack.sock
   ```

3. **Redeploy after adding the volume mount**:
   ```bash
   phala deploy --interactive
   ```

### Cannot SSH into CVM

1. Add your SSH public key:
   ```bash
   phala ssh-keys add
   ```

2. Restart the CVM:
   ```bash
   phala cvms restart --interactive
   ```

3. Try connecting again:
   ```bash
   phala ssh --interactive
   ```

## Cost Estimation

Pricing varies by instance type and region. Example for `tdx.small`:

- **Compute**: ~$0.058/hour
- **Storage**: $0.003/hour per 20GB
- **Monthly estimate**: ~$44 for small instance

Check current pricing at https://cloud.phala.network/pricing

## Resources

### Documentation

- [Phala Cloud Docs](https://docs.phala.com/phala-cloud)
- [Getting Started Guide](https://docs.phala.com/phala-cloud/getting-started/start-from-cloud-ui)
- [Secure Environment Variables](https://docs.phala.com/phala-cloud/cvm/set-secure-environment-variables)
- [CLI Reference](https://docs.phala.com/phala-cloud/cli)

### Phala Network

- [Phala Cloud Dashboard](https://cloud.phala.network)
- [Phala Network](https://phala.network)
- [GitHub](https://github.com/Phala-Network)
- [Discord](https://discord.gg/phala)

### This Project

- [Main README](../README.md)
- [Local Setup](./LOCAL_SETUP.md)
- [Docker Guide](./DOCKER.md)
- [API Reference](./API_REFERENCE.md)

## Next Steps

After successful deployment:

1. **Test the API**: Make requests to your endpoints
2. **Monitor logs**: Use `phala logs --interactive` to monitor activity
3. **Set up monitoring**: Consider external monitoring for production
4. **Configure custom domain**: Set up custom DNS if needed
5. **Scale**: Adjust instance type or create replicas as needed

For production deployments, review [Phala's best practices](https://docs.phala.com/phala-cloud/best-practices).

## Comparison with Other Deployment Modes

| Feature | Local (No Docker) | Local (Docker) | Phala Cloud |
|---------|------------------|----------------|-------------|
| **Setup Complexity** | Low | Medium | Medium |
| **Hot Reload** | ✅ Yes | ✅ Yes (dev mode) | ❌ No |
| **TEE Environment** | ❌ No | ❌ No | ✅ Yes (Intel TDX) |
| **Attestation** | ❌ No | ❌ No | ✅ Yes |
| **TLS** | ✅ Self-signed | ❌ HTTP | ✅ Phala-managed |
| **Secret Encryption** | ⚠️  Manual | ⚠️  Manual | ✅ Browser-to-TEE |
| **Best For** | Development | Testing | Production |

See:
- [Local Setup Guide](./LOCAL_SETUP.md) - Run without Docker
- [Docker Guide](./DOCKER.md) - Run with Docker locally
