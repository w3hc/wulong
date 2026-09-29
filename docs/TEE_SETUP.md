# TEE Setup

Wulong runs on one TEE: an Intel TDX confidential VM managed by [dstack](https://github.com/Dstack-TEE/dstack), such as [Phala Cloud](https://cloud.phala.network/). Other platforms (AMD SEV-SNP, native TDX, AWS Nitro) are not supported. Their earlier code paths were stubs, and they were removed so that an attestation never looks real without being real.

For the deployment itself, see [PHALA_CONFIG.md](PHALA_CONFIG.md).

## Table of Contents

- [How attestation works](#how-attestation-works)
- [Fail-closed startup](#fail-closed-startup)
- [Measurements](#measurements)
- [Development without a TEE](#development-without-a-tee)
- [Security considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## How attestation works

`TeePlatformService` (`src/attestation/tee-platform.service.ts`) asks the dstack guest agent for a TDX quote through `POST /GetQuote` on `/var/run/dstack.sock`, via Wulong's own client (`src/keys/dstack-v1.client.ts`). The socket must be mounted into the container, as `docker-compose.yml` does.

`GET /chest/attestation` returns:

- `report`: the base64 TDX v4 quote
- `measurements`: `mrtd` and `rtmr0` to `rtmr3`, read from the quote (`src/attestation/tdx-quote.ts`)
- `eventLog`: the dstack event log (JSON), which replays RTMR0–3
- `reportData`: the quote's 64-byte `report_data`, which commits to Wulong's public keys, its TLS certificate and the client's nonce ([KEY_DERIVATION.md](KEY_DERIVATION.md#report_data))

The service checks that every quote carries the `report_data` it asked for.

## Fail-closed startup

With `NODE_ENV=production`, Wulong refuses to start when:

- `/var/run/dstack.sock` is absent;
- `DSTACK_SIMULATOR_ENDPOINT` is set (the simulator's quotes and keys prove nothing);
- the first quote cannot be generated or parsed, or does not carry the requested `report_data`.

There is no mock fallback in production.

## Measurements

Quote offsets (TDX v4: a 48-byte header, then the TD report body):

| Field | Offset | Size | What it measures on dstack |
| --- | --- | --- | --- |
| MRTD | 184 | 48 | Virtual firmware (OVMF) |
| RTMR0 | 376 | 48 | Virtual hardware: CPU count, memory size, devices |
| RTMR1 | 424 | 48 | Linux kernel |
| RTMR2 | 472 | 48 | Kernel command line (including the rootfs hash) and initrd |
| RTMR3 | 520 | 48 | The app: app id, compose hash, instance id, key provider |
| REPORTDATA | 568 | 64 | Wulong's key and nonce commitment |

**RTMR3 identifies the app.** MRTD and RTMR0–2 identify the dstack OS image and the VM size, and are the same for every app on that image. Comparing MRTD alone, which is what the removed `measurement` field held (and at the wrong offset, 112, which is MRSIGNERSEAM), says nothing about which code runs.

### Reproducing RTMR3 from the compose file

1. **Compose hash.** Phala Cloud deploys an `app-compose.json` that embeds `docker-compose.yml`, and its compose hash is the SHA-256 of that file. Get it with `phala cvms attestation` or from the dashboard, and check that its `docker_compose_file` is this repository's `docker-compose.yml` at the release you audit, with the image pinned by digest. Then check that the digest is the one published for that release, and rebuild it to compare (see [DOCKER.md](./DOCKER.md#checking-a-digest)).
2. **Replay.** Start from 48 zero bytes, and for each event of `eventLog` whose `imr` is 3, in order, compute `rtmr3 = SHA-384(rtmr3 || event.digest)`. The result must equal `measurements.rtmr3`, and the quote's RTMR3 once its signature is verified.
3. **Check the events.** Recompute each event's digest from its name and payload. In dstack's v1 format, the digest is `SHA-384(event_type_le32 || ":" || event || ":" || payload)` with `event_type = 0x08000001`; v2 hashes a canonical JSON form (see [`runtime_events.rs`](https://github.com/Dstack-TEE/dstack/blob/master/dstack/cc-eventlog/src/runtime_events.rs)). Then check that the `compose-hash` event's payload is the compose hash from step 1, and that `app-id` is the app you expect.

The dstack JS and Python SDKs provide `replayRtmrs()`, and [dstack-verifier](https://github.com/Dstack-TEE/dstack/tree/master/dstack/verifier) does the whole check.

### Reproducing MRTD and RTMR0–2

Build the dstack OS image at the version the CVM runs and compute its measurements with [dstack-mr](https://github.com/Dstack-TEE/dstack/tree/master/dstack/dstack-mr), giving the CVM's CPU count and memory. See dstack's [TDX attestation guide](https://github.com/Dstack-TEE/dstack/blob/master/docs/attestation-tdx.md).

### What `pnpm verify:attestation` checks

It checks the key binding, parses the quote, and checks that the returned `measurements` are the ones in the quote. It does not verify the quote signature, TCB status or the RTMR3 replay: use dcap-qvl, dstack-verifier or Phala's verifier for those ([scripts/README.md](../scripts/README.md)).

## Development without a TEE

Outside production:

- with `DSTACK_SIMULATOR_ENDPOINT` set, quotes come from the [dstack simulator](https://github.com/Dstack-TEE/dstack/tree/master/sdk/simulator) and have `platform: "intel-tdx"`;
- without the simulator or the socket, `GET /chest/attestation` returns `platform: "none"`, a placeholder `report`, and `measurements` and `eventLog` set to `null`. Clients must refuse it.

See [LOCAL_SETUP.md](LOCAL_SETUP.md).

## Security considerations

**Protected against**:
- A malicious host operator reading memory
- Network eavesdropping (TLS terminates in the enclave)
- Log-based data exfiltration

**Not protected against**:
- Side-channel attacks (see [SIDE_CHANNEL_ATTACKS.md](SIDE_CHANNEL_ATTACKS.md))
- Physical attacks on the hardware
- Compromised TDX firmware or hardware
- Application logic bugs

**You must trust**:
1. Intel (the TDX module and the quote signing chain)
2. The dstack OS image, which you can rebuild and measure (MRTD, RTMR0–2)
3. The app code and compose file, which RTMR3 identifies
4. The dstack KMS that derives Wulong's keys ([KEY_DERIVATION.md](KEY_DERIVATION.md))

## Troubleshooting

### Startup fails with "No dstack guest agent at /var/run/dstack.sock"

The socket is not mounted. `docker-compose.yml` must keep:

```yaml
volumes:
  - /var/run/dstack.sock:/var/run/dstack.sock
```

### Startup fails with "The first TDX quote could not be generated"

The guest agent answered, but the quote failed, did not parse as a TDX v4 quote, or did not carry the requested `report_data`. The logs give the cause.

### `platform` is `none`

You are not in production, and neither the socket nor `DSTACK_SIMULATOR_ENDPOINT` is available. In production this state cannot happen: the app refuses to start.
