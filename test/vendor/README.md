# Vendored test dependencies

## QUnit 1.23.1 — pinned, do not upgrade

`qunit-1.23.1.js` / `qunit-1.23.1.css` are vendored on purpose.

**1.23.1 is the last QUnit release that supports Internet Explorer 8**, which
this library still targets. Newer QUnit versions drop IE8 (and older) support,
so upgrading would break the test harness on the very browsers we pin this
version for.

These files are committed (rather than pulled from a CDN) so that:

- the test suite runs offline and deterministically;
- there is no runtime dependency on third-party CDN availability or TLS that
  IE8 cannot negotiate;
- the exact reviewed code is what executes.

They are **not** published to npm — the package `files` allowlist only ships
`dist/`, `types/`, and the docs/license, so this folder adds nothing to the
installed package size.

Used by [`../SubtleTests.html`](../SubtleTests.html).
