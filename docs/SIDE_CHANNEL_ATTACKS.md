# Side-Channel Attack Protections

This document outlines defensive techniques to protect against side-channel attacks, including timing and cache attacks.

## Timing Attacks

- **Constant-time operations**: Use algorithms that take the same amount of time regardless of input values (especially for cryptographic operations, comparisons)
- **Avoid branching on secrets**: Don't use conditional logic that depends on secret data
- **Add random delays**: Introduce jitter to obscure timing patterns (though this alone isn't sufficient)
- **Use timing-safe comparison functions**: For comparing secrets, use functions like `crypto.timingSafeEqual()` in Node.js

## Cache Attacks

- **Cache partitioning**: Isolate sensitive operations in separate cache domains
- **Disable CPU optimizations**: In critical contexts, disable features like hyper-threading, speculative execution
- **Memory access patterns**: Ensure memory access doesn't depend on secret values
- **Hardware mitigations**: Use CPUs with built-in protections (Intel CET, ARM Pointer Authentication)
- **Software updates**: Keep systems patched against Spectre/Meltdown variants

## General Practices

- **TEE isolation**: Use Trusted Execution Environments (like SGX, SEV, TrustZone) to isolate sensitive computations
- **Minimize attack surface**: Reduce the amount of sensitive data processed and its exposure time
- **Input/output sanitization**: Prevent attackers from controlling inputs that could be used to probe timing
- **Monitoring**: Detect unusual timing patterns or cache behavior that might indicate an attack

## What Wulong Does

Three global components, ported from [zk-api](https://github.com/w3hc/zk-api), limit what a response reveals beyond its body:

| Component | Protection |
| --- | --- |
| [`TimingProtectionInterceptor`](../src/interceptors/timing-protection.interceptor.ts) | Holds every response, success or error, until 100 ms plus 0–20 ms of random jitter (`crypto.randomInt`) have passed since the handler started. Slower handlers are not padded further |
| [`MetadataSanitizerInterceptor`](../src/interceptors/metadata-sanitizer.interceptor.ts) | Removes `Server`, `X-Powered-By`, `ETag`, `Last-Modified`, `Vary`, `Via`, `Age`, and tracing and CDN headers from every response, and sets `Cache-Control: no-store`, `Pragma: no-cache`, `Expires: 0`. Express's ETag, added after interceptors run, is disabled in [`configureResponseHeaders`](../src/http/http-config.ts) |
| [`RequestSanitizerMiddleware`](../src/middleware/request-sanitizer.middleware.ts) | Deletes `User-Agent`, `Referer`, `Origin`, `Accept-Language`, `Accept-Encoding`, client hints, `Sec-Fetch-*`, `DNT` and client-IP headers set by CDNs from every request before any route code or log line sees them |

They differ from zk-api's versions in three ways:

- zk-api delays and sanitizes successful responses only; here errors are covered too, since "slot not found" is the answer worth hiding.
- zk-api also deletes `X-Forwarded-For` and reports every client as `0.0.0.0`. The rate limiter keys on the client IP, which Express reads from `X-Forwarded-For` behind a TLS-terminating proxy, so that would put all clients in one bucket. Both are kept.
- zk-api shortens its timing floor when `NODE_ENV` is `test`; here tests use fake timers and exercise the production code path.

`GET /chest/access/:slot` answers `404 Slot not found` both when the slot does not exist and when the caller is not an owner, and every decryption failure returns the same `Failed to decrypt secret`. Validation errors state the rule broken, never the value submitted.

Limits:

- Guards run before interceptors, so SIWE rejections (`401`) and rate-limit rejections (`429`) are not delayed. They depend only on the request itself, not on stored data.
- A handler slower than the floor, such as a successful ML-KEM decryption, still takes longer than a `404`. Only owners of a slot reach that path, and they already know it exists.
- IP addresses are visible to the process. Hide them at the network level if needed.

## Application-Specific Recommendations

For this NestJS TEE attestation service, the most relevant protections include:

1. Constant-time cryptographic operations for all attestation verification
2. Leveraging the TEE's hardware isolation capabilities to protect sensitive operations
3. Using timing-safe comparison functions when validating attestation tokens or signatures
4. Ensuring attestation response times don't leak information about the validity or content of requests
