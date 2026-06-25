// Build script for @microsoft/msrcrypto.
//
// Replaces the previous Gulp pipeline. Single dev dependency: esbuild.
//
// Pipeline:
//   1. Concatenate the full source list         -> lib/msrcrypto.js
//      - strip per-file leading license headers (avoid ~30 duplicate copies)
//      - strip /* debug-block */ ... /* end-debug-block */ regions
//      - prepend a single LICENSE header
//      (the scripts/subtle/* files are concatenated inline, in order, so the
//       msrcryptoSubtle IIFE scope is formed by head.js ... tail.js)
//   2. esbuild minify lib/msrcrypto.js          -> lib/msrcrypto.min.js
//      - target: es5  (source is ES5; refuse to introduce ES6+ syntax)
//      - minifySyntax: false  (preserves obj["catch"] form needed for IE8)
//
// Usage:  npm run build
//         npm run build -- --watch

import * as esbuild from "esbuild";
import { readFile, writeFile, rm, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { performance } from "node:perf_hooks";

const LICENSE_FILE = "LICENSE";
const FULL_BUNDLE_OUT = "lib/msrcrypto.js";
const MIN_BUNDLE_OUT = "lib/msrcrypto.min.js";

// Single source of truth for the library version: package.json. The value is
// injected into the bundle at build time so the shipped msrCryptoVersion can
// never drift from the published package version.
const PKG_VERSION = JSON.parse(await readFile("package.json", "utf8")).version;
const VERSION_RE = /var msrCryptoVersion = "[^"]*";/;

const fullBuild = [
    "scripts/bundleHead.js",
    "scripts/operations.js",
    "scripts/global.js",
    "scripts/utilities.js",
    "scripts/asn1.js",
    "scripts/worker.js",
    "scripts/jwk.js",
    "scripts/cryptoMath.js",
    "scripts/cryptoECC.js",
    "scripts/curves_NIST.js",
    "scripts/curves_BN.js",
    "scripts/curves_NUMS.js",
    "scripts/sha.js",
    "scripts/sha1.js",
    "scripts/sha256.js",
    "scripts/sha512.js",
    "scripts/hmac.js",
    "scripts/aes.js",
    "scripts/aes-cbc.js",
    "scripts/aes-gcm.js",
    "scripts/aes-kw.js",
    "scripts/random.js",
    "scripts/entropy.js",
    "scripts/prime.js",
    "scripts/rsa-base.js",
    "scripts/rsa-oaep.js",
    "scripts/rsa-pkcs1.js",
    "scripts/rsa-pss.js",
    "scripts/rsa.js",
    "scripts/concat.js",
    "scripts/pbkdf2.js",
    "scripts/hkdf.js",
    "scripts/hkdf-ctr.js",
    "scripts/ecdh.js",
    "scripts/ecdsa.js",
    "scripts/subtle/head.js",
    "scripts/subtle/syncWorker.js",
    "scripts/subtle/operations.js",
    "scripts/subtle/keyManager.js",
    "scripts/subtle/workerManager.js",
    "scripts/subtle/subtleInterface.js",
    "scripts/subtle/tail.js",
    "scripts/wrapKey.js",
    "scripts/bundleTail.js",
    "scripts/subtle/promises.js",
];

const DEBUG_BLOCK_RE =
    /\/\*\s*debug-block\s*\*\/[\s\S]*?\/\*\s*end-debug-block\s*\*\//g;

// Strip all comments from source (replicates gulp-strip-comments behaviour).
// Handles // line comments, /* block comments */, string literals, and
// regex literals — so it does not accidentally strip comment-like text
// inside those constructs (e.g. /https?:\/\//).
//
// Regex-vs-division disambiguation: a bare / is a regex literal start when
// the previous significant (non-whitespace) character is NOT one that can
// end a primary expression (identifier, digit, ), ]).  This heuristic is
// standard and correct for all ES5 patterns found in this codebase.
function stripAllComments(src) {
    let out = "";
    let i = 0;
    const n = src.length;
    var prevSig = ""; // last non-whitespace character written to output

    function isOutAtLineStart() {
        var p = out.length - 1;
        while (p >= 0 && (out[p] === " " || out[p] === "\t" || out[p] === "\r")) {
            p--;
        }
        return p < 0 || out[p] === "\n";
    }

    function trimOutLineIndent() {
        while (out.length > 0) {
            var ch = out[out.length - 1];
            if (ch === " " || ch === "\t" || ch === "\r") {
                out = out.slice(0, out.length - 1);
            } else {
                break;
            }
        }
    }

    while (i < n) {
        var c = src[i];

        if (c === "/" && i + 1 < n) {
            // Block comment
            if (src[i + 1] === "*") {
                var bEnd = src.indexOf("*/", i + 2);
                var bNext = bEnd === -1 ? n : bEnd + 2;
                if (bNext < n && isOutAtLineStart()) {
                    var bi = bNext;
                    while (bi < n && (src[bi] === " " || src[bi] === "\t" || src[bi] === "\r")) {
                        bi++;
                    }
                    if (bi < n && src[bi] === "\n") {
                        trimOutLineIndent();
                        i = bi + 1;
                        continue;
                    }
                }
                i = bNext;
                continue;
            }
            // Line comment
            if (src[i + 1] === "/") {
                var lEnd = src.indexOf("\n", i + 2);
                if (lEnd === -1) {
                    i = n;
                    continue;
                }
                if (isOutAtLineStart()) {
                    trimOutLineIndent();
                    i = lEnd + 1;
                    continue;
                }
                i = lEnd; // keep newline for end-of-line comments after code
                continue;
            }
            // Regex literal when previous significant char cannot end an expression
            if (!/[a-zA-Z0-9_$)\]]/.test(prevSig)) {
                out += c; i++; // opening /
                while (i < n) {
                    var rc = src[i];
                    if (rc === "\\") {                  // escape sequence
                        out += rc; i++;
                        if (i < n) { out += src[i++]; }
                        continue;
                    }
                    if (rc === "[") {                   // character class [...]
                        out += rc; i++;
                        while (i < n) {
                            var cc = src[i];
                            out += cc; i++;
                            if (cc === "\\") { if (i < n) { out += src[i++]; } continue; }
                            if (cc === "]") break;
                        }
                        continue;
                    }
                    out += rc; i++;
                    if (rc === "/") break;              // closing /
                }
                // consume regex flags (g i m y)
                while (i < n && /[gimy]/.test(src[i])) { out += src[i++]; }
                prevSig = "/";
                continue;
            }
            // Otherwise: division operator — fall through to default
        }

        // String literals
        if (c === '"' || c === "'") {
            var q = c;
            out += c; i++;
            while (i < n) {
                var sc = src[i];
                out += sc; i++;
                if (sc === "\\") { if (i < n) { out += src[i++]; } continue; }
                if (sc === q) break;
            }
            prevSig = q;
            continue;
        }

        out += c; i++;
        if (c !== " " && c !== "\t" && c !== "\r" && c !== "\n") prevSig = c;
    }
    return out;
}

// Remove trailing horizontal whitespace and collapse long runs of blank lines
// introduced by comment stripping.
function collapseEmptyLines(src) {
    return src
        .replace(/[ \t]+\n/g, "\n")
        .replace(/\n{3,}/g, "\n\n")
        .replace(/\n+$/, "\n");
}

// Remove only the LEADING comment block(s) from a source file.
// This drops the per-file license header without touching inline comments,
// strings, or regex literals further down. Safe for ES5 sources.
// Also skips a leading UTF-8 BOM (U+FEFF) — 37 of the source files in this
// repo start with one, and without skipping it the loop bails out before
// reaching the comment that follows.
function stripLeadingComments(src) {
    let i = 0;
    const n = src.length;
    while (i < n) {
        const c = src[i];
        if (c === " " || c === "\t" || c === "\r" || c === "\n" || c === "\uFEFF") {
            i++;
            continue;
        }
        if (c === "/" && src[i + 1] === "*") {
            const end = src.indexOf("*/", i + 2);
            if (end === -1) break;
            i = end + 2;
            continue;
        }
        if (c === "/" && src[i + 1] === "/") {
            const end = src.indexOf("\n", i + 2);
            i = end === -1 ? n : end + 1;
            continue;
        }
        break;
    }
    return src.slice(i);
}

async function concatFiles(files, { stripHeader } = { stripHeader: true }) {
    const parts = await Promise.all(
        files.map(async (f) => {
            let text = await readFile(f, "utf8");
            // Strip BOM unconditionally — embedded BOMs in the middle of a
            // concatenated bundle are invalid as a token.
            if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
            return stripHeader ? stripLeadingComments(text) : text;
        }),
    );
    return parts.join("\n");
}

async function ensureDir(path) {
    const dir = dirname(path);
    if (!existsSync(dir)) {
        await mkdir(dir, { recursive: true });
    }
}

async function cleanOutputs() {
    for (const f of [FULL_BUNDLE_OUT, MIN_BUNDLE_OUT]) {
        if (existsSync(f)) {
            await rm(f, { force: true });
        }
    }
}

function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

async function build() {
    const t0 = performance.now();

    const license = await readFile(LICENSE_FILE, "utf8");

    // 1. lib/msrcrypto.js — full UMD bundle.
    let fullBundle = await concatFiles(fullBuild);
    fullBundle = fullBundle.replace(DEBUG_BLOCK_RE, "");
    fullBundle = stripAllComments(fullBundle);
    fullBundle = collapseEmptyLines(fullBundle);
    // Inject the package.json version so the bundle's msrCryptoVersion always
    // matches the published package version.
    if (!VERSION_RE.test(fullBundle)) {
        throw new Error("build: could not find msrCryptoVersion declaration to inject version");
    }
    fullBundle = fullBundle.replace(VERSION_RE, `var msrCryptoVersion = "${PKG_VERSION}";`);
    fullBundle = license + "\n" + fullBundle;
    await ensureDir(FULL_BUNDLE_OUT);
    await writeFile(FULL_BUNDLE_OUT, fullBundle);

    // 2. lib/msrcrypto.min.js — minified.
    // minifySyntax is intentionally OFF so esbuild does not rewrite
    // obj["catch"] to obj.catch (catch is a reserved word on IE8).
    const minified = await esbuild.transform(fullBundle, {
        loader: "js",
        target: "es5",
        minifyWhitespace: true,
        minifyIdentifiers: true,
        minifySyntax: false,
        legalComments: "none",
        charset: "utf8",
    });
    await writeFile(MIN_BUNDLE_OUT, license + "\n" + minified.code);

    const t1 = performance.now();

    const sizes = await Promise.all(
        [FULL_BUNDLE_OUT, MIN_BUNDLE_OUT].map(async (f) => {
            const buf = await readFile(f);
            return { file: f, bytes: buf.length };
        }),
    );

    console.log(`built in ${(t1 - t0).toFixed(0)} ms (v${PKG_VERSION})`);
    for (const s of sizes) {
        console.log(`  ${s.file.padEnd(24)} ${fmtBytes(s.bytes)}`);
    }
}

async function watch() {
    const chokidar = await import("node:fs/promises");
    const { watch: fsWatch } = await import("node:fs");
    const all = new Set([...fullBuild, LICENSE_FILE]);
    let timer = null;
    const rebuild = () => {
        clearTimeout(timer);
        timer = setTimeout(() => {
            build().catch((err) => console.error(err));
        }, 50);
    };
    await build();
    console.log("watching for changes...");
    for (const f of all) {
        try {
            fsWatch(f, rebuild);
        } catch {
            // file may not exist yet — that's fine
        }
    }
    // Also watch the directories that contain source files so newly-added
    // files trigger rebuilds.
    fsWatch("scripts", { recursive: true }, rebuild);
}

const args = process.argv.slice(2);
if (args.includes("--clean")) {
    await cleanOutputs();
    console.log("cleaned build outputs");
} else if (args.includes("--watch")) {
    await cleanOutputs();
    await watch();
} else {
    await cleanOutputs();
    await build();
}
