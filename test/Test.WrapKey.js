//*******************************************************************************
//
//    Copyright 2020 Microsoft
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//
//*******************************************************************************

"use strict";

QUnit.module("Wrap Key");

// Exercises subtle.wrapKey / subtle.unwrapKey as a round-trip: a freshly
// generated AES key is exported, wrapped with a wrapping key, unwrapped with
// the matching unwrapping key, and the recovered key material is compared to
// the original. A match proves wrap and unwrap are inverse operations for the
// given algorithm and key format.
function wrapUnwrapRoundTrip(assert, options) {
    var done = assert.async();

    var originalRaw;
    var keyToWrap;
    var wrappingKey;
    var unwrappingKey;

    Promise.all([options.generateKeyToWrap(), options.generateWrappingKeys()])
        .then(function(results) {
            keyToWrap = results[0];
            wrappingKey = results[1].wrappingKey;
            unwrappingKey = results[1].unwrappingKey;
            return subtle.exportKey("raw", keyToWrap);
        })
        .then(function(raw) {
            originalRaw = testShared.toArray(raw);
            return subtle.wrapKey(options.format, keyToWrap, wrappingKey, options.wrapAlgorithm);
        })
        .then(function(wrapped) {
            // Pass the wrapped key through unchanged: native WebCrypto requires a
            // BufferSource (ArrayBuffer/TypedArray) here, not a plain Array.
            return subtle.unwrapKey(options.format, wrapped, unwrappingKey,
                options.wrapAlgorithm, options.unwrappedKeyAlgorithm, true, options.unwrappedKeyUsages);
        })
        .then(function(unwrappedKey) {
            return subtle.exportKey("raw", unwrappedKey);
        })
        .then(function(roundTrippedRaw) {
            assert.deepEqual(testShared.toArray(roundTrippedRaw), originalRaw,
                "unwrapped key material matches the original");
            done();
        })
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](function(err) {
            assert.ok(false, "round-trip failed: " + (err && (err.name || err)));
            done();
        });
}

// The key that gets wrapped in every test: an extractable AES-CBC key whose
// raw bytes can be compared before and after the round-trip.
function generateAesKeyToWrap() {
    return subtle.generateKey({ name: "AES-CBC", length: 128 }, true, ["encrypt", "decrypt"]);
}

// Builds a symmetric wrapping/unwrapping pair where the same key does both.
function symmetricWrappingKeys(algorithm) {
    return function() {
        return subtle.generateKey(algorithm, true, ["wrapKey", "unwrapKey"]).then(function(key) {
            return { wrappingKey: key, unwrappingKey: key };
        });
    };
}

// Builds an RSA-OAEP key pair: the public key wraps, the private key unwraps.
function rsaWrappingKeys() {
    // Native WebCrypto requires publicExponent as a Uint8Array; fall back to a
    // plain Array where TypedArrays are unavailable (e.g. IE8 + msrCrypto).
    var publicExponent = (typeof Uint8Array !== "undefined")
        ? new Uint8Array([0x01, 0x00, 0x01])
        : [0x01, 0x00, 0x01];

    return subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 1024, publicExponent: publicExponent, hash: "SHA-256" },
        true,
        ["wrapKey", "unwrapKey"])
        .then(function(keyPair) {
            return { wrappingKey: keyPair.publicKey, unwrappingKey: keyPair.privateKey };
        });
}

var wrapIv = (typeof Uint8Array !== "undefined")
    ? new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    : [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

QUnit.test("AES-KW wraps and unwraps a raw AES key", function(assert) {
    wrapUnwrapRoundTrip(assert, {
        format: "raw",
        wrapAlgorithm: { name: "AES-KW" },
        generateKeyToWrap: generateAesKeyToWrap,
        generateWrappingKeys: symmetricWrappingKeys({ name: "AES-KW", length: 256 }),
        unwrappedKeyAlgorithm: { name: "AES-CBC" },
        unwrappedKeyUsages: ["encrypt", "decrypt"]
    });
});

QUnit.test("AES-CBC wraps and unwraps a raw AES key", function(assert) {
    wrapUnwrapRoundTrip(assert, {
        format: "raw",
        wrapAlgorithm: { name: "AES-CBC", iv: wrapIv },
        generateKeyToWrap: generateAesKeyToWrap,
        generateWrappingKeys: symmetricWrappingKeys({ name: "AES-CBC", length: 256 }),
        unwrappedKeyAlgorithm: { name: "AES-CBC" },
        unwrappedKeyUsages: ["encrypt", "decrypt"]
    });
});

QUnit.test("AES-GCM wraps and unwraps a raw AES key", function(assert) {
    wrapUnwrapRoundTrip(assert, {
        format: "raw",
        wrapAlgorithm: { name: "AES-GCM", iv: wrapIv },
        generateKeyToWrap: generateAesKeyToWrap,
        generateWrappingKeys: symmetricWrappingKeys({ name: "AES-GCM", length: 256 }),
        unwrappedKeyAlgorithm: { name: "AES-CBC" },
        unwrappedKeyUsages: ["encrypt", "decrypt"]
    });
});

QUnit.test("AES-GCM wraps and unwraps a key in jwk format", function(assert) {
    wrapUnwrapRoundTrip(assert, {
        format: "jwk",
        wrapAlgorithm: { name: "AES-GCM", iv: wrapIv },
        generateKeyToWrap: generateAesKeyToWrap,
        generateWrappingKeys: symmetricWrappingKeys({ name: "AES-GCM", length: 256 }),
        unwrappedKeyAlgorithm: { name: "AES-CBC" },
        unwrappedKeyUsages: ["encrypt", "decrypt"]
    });
});

QUnit.test("RSA-OAEP wraps and unwraps a raw AES key", function(assert) {
    wrapUnwrapRoundTrip(assert, {
        format: "raw",
        wrapAlgorithm: { name: "RSA-OAEP" },
        generateKeyToWrap: generateAesKeyToWrap,
        generateWrappingKeys: rsaWrappingKeys,
        unwrappedKeyAlgorithm: { name: "AES-CBC" },
        unwrappedKeyUsages: ["encrypt", "decrypt"]
    });
});
