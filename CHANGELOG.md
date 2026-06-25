# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `SubtleCrypto.generateKey` for RSA algorithms now honors the requested key
  usages (routing each usage to the public or private key it applies to)
  instead of forcing a fixed pair. Generating an `RSA-OAEP` key with
  `["wrapKey", "unwrapKey"]` now yields keys usable with `wrapKey`/`unwrapKey`.

### Removed

- Dead, unreachable `wrapKey.js` module (legacy JWE-style key wrapping that was
  never dispatched) and its orphaned JWK byte-serializer helper. The public
  `wrapKey`/`unwrapKey` continue to work via the standard
  export-then-encrypt / decrypt-then-import path.

## [1.7.0] - 2026-06-25

### Added

- TypeScript declarations ([`types/msrCrypto.d.ts`](types/msrCrypto.d.ts)) were
  rewritten to describe the library's own `MsrCrypto` surface and to resolve for
  the `@microsoft/msrcrypto` import specifier (via `export =`).
- An `Errors` test module that asserts the public APIs reject/throw with the
  correct error names, plus the previously-unwired `CryptoKey` test module.
- npm package metadata (`keywords`, `author`, `homepage`, `bugs`, `exports`,
  `sideEffects`, `publishConfig`) and a `prepublishOnly` build guard.
- Dormant GitHub Actions release workflow that builds, verifies the package,
  and publishes to npm with provenance on tagged releases.

### Changed

- `SubtleCrypto` algorithm parameters now accept a string `AlgorithmIdentifier`
  (e.g. `"SHA-256"`) in addition to an object, matching the W3C Web Crypto spec.
- `SubtleCrypto` methods now surface invalid input and unsupported algorithms as
  a rejected promise instead of throwing synchronously, per the Web Crypto
  contract. Missing or wrong-type arguments reject with a `TypeError`.
- Errors raised by the library are now `DOMException`s with specification names
  (`NotSupportedError`, `OperationError`, `InvalidAccessError`, `DataError`),
  falling back to an `Error` carrying the name and legacy code on engines
  without a `DOMException` constructor (e.g. IE8).
- `getRandomValues` now throws `QuotaExceededError` for requests larger than
  65,536 bytes and `TypeMismatchError` for floating-point typed arrays.
- The library version is now injected into the bundle from `package.json` at
  build time, eliminating version drift between the package and the bundle.
- Repository layout: built output moved from `lib/` to `dist/`, type
  declarations from `definitions/` to `types/`, and sources under `src/`. The
  published `main`/`types` paths are resolved through `package.json`, so
  installs via the package name are unaffected; only deep paths such as
  `@microsoft/msrcrypto/lib/...` changed.

### Fixed

- HMAC `generateKey` now honors the optional `length` parameter correctly (bits,
  not bytes) and zeroes the unused trailing bits of the final byte for
  non-byte-aligned lengths, matching native Web Crypto behavior.
- AES `generateKey` (CBC, GCM, KW) now rejects key lengths other than 128, 192,
  or 256 bits instead of accepting any multiple of 8.
- Removed a stray `console.log` that leaked exported key material during
  `wrapKey`.
- Fixed an error in the worker result path that threw when assigning to the
  read-only `DOMException.code` property.

## [1.6.0]

- Automatic web-worker usage is disabled by default. When enabled, it may cause
  problems when the library is bundled with other scripts.
- `raw` key import support for HMAC & ECDH.
- `spki` public key import for RSA.
- `wrapKey` support for AES-CBC, AES-GCM, RSA-OAEP.
- PBKDF2 key derivation algorithm.
- Additional side-channel protection.
- Moved source to GitHub.

## [1.5.0]

- Added support for streaming input/output data to crypto calls.
- Allow concurrent crypto calls of the same type at the same time.
- Added `raw` keyImport/keyExport format for HMAC, AES-CBC, AES-GCM.
- Added `IE11PromiseWrapper.js` to wrap the IE11 non-standard Web Crypto API so
  it behaves like the current standard Promise-based API.
- Removed RSASSA-PKCS1-v1_5 encrypt/decrypt algorithm (obsolete, no longer
  supported by modern browsers).
- Added TypeScript definitions (`msrCrypto.d.ts`).
- Moved the Promise polyfill outside of the library so the built-in browser
  version can be used when available.

## [1.4.0]

- Updated the API to the latest Web Crypto API spec and modern browser
  implementations.
- Promises are now supported; the IE11-style event callbacks were removed. This
  is a breaking change for code using the pre-1.4 `onComplete`/`onError`
  calling conventions.

[Unreleased]: https://github.com/microsoft/MSR-JavaScript-Crypto/compare/v1.6.6...HEAD
[1.6.0]: https://github.com/microsoft/MSR-JavaScript-Crypto/releases/tag/v1.6.0
[1.5.0]: https://github.com/microsoft/MSR-JavaScript-Crypto/releases/tag/v1.5.0
[1.4.0]: https://github.com/microsoft/MSR-JavaScript-Crypto/releases/tag/v1.4.0
