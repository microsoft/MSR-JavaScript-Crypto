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

QUnit.module("Errors");

// Asserts that 'promise' rejects (never resolves) with a DOMException whose
// name matches 'expectedName'.
function assertRejectsWith(assert, promise, expectedName, description) {
    var done = assert.async();

    promise
        .then(function() {
            assert.ok(false, description + ": expected a rejection but the promise resolved");
            done();
        })
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](function(err) {
            assert.equal(err && err.name, expectedName, description + ": rejects with " + expectedName);
            if (typeof DOMException !== "undefined") {
                assert.ok(err instanceof DOMException, description + ": error is a DOMException");
            }
            done();
        });
}

// A subtle method that is given a bad algorithm/parameters must surface the
// error as a rejected promise, never as a synchronous throw (WebCrypto contract).
QUnit.test("subtle methods reject (do not throw synchronously) on bad input", function(assert) {
    var data = [97, 98, 99];

    var promise = subtle.digest({ name: "NOT-A-REAL-ALGORITHM" }, data);

    assert.ok(promise && typeof promise.then === "function",
        "digest returns a promise even for an unsupported algorithm");

    assertRejectsWith(assert, promise, "NotSupportedError",
        "digest with an unrecognized algorithm");
});

QUnit.test("unrecognized algorithm rejects with NotSupportedError", function(assert) {
    assertRejectsWith(assert, subtle.encrypt({ name: "BOGUS-CBC" }, {}, [1, 2, 3]),
        "NotSupportedError", "encrypt with an unrecognized algorithm");
});

QUnit.test("missing required argument rejects with a TypeError", function(assert) {
    var done = assert.async();

    subtle.digest()
        .then(function() {
            assert.ok(false, "digest() with no arguments should reject");
            done();
        })
        // tslint:disable-next-line: no-string-literal
        ["catch"](function(err) {
            assert.ok(err instanceof TypeError, "missing argument rejects with a TypeError");
            done();
        });
});

QUnit.test("AES-GCM rejects with OperationError when authentication fails", function(assert) {
    var done = assert.async();
    var iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
        .then(function(key) {
            return subtle.encrypt({ name: "AES-GCM", iv: iv }, key, [1, 2, 3, 4, 5])
                .then(function(cipher) {
                    var tampered = testShared.toArray(cipher);
                    tampered[0] ^= 0xff; // corrupt the ciphertext so the tag check fails
                    return subtle.decrypt({ name: "AES-GCM", iv: iv }, key, tampered);
                });
        })
        .then(function() {
            assert.ok(false, "decrypting tampered AES-GCM data should reject");
            done();
        })
        // tslint:disable-next-line: no-string-literal
        ["catch"](function(err) {
            assert.equal(err && err.name, "OperationError", "tampered AES-GCM data rejects with OperationError");
            if (typeof DOMException !== "undefined") {
                assert.ok(err instanceof DOMException, "error is a DOMException");
            }
            done();
        });
});

QUnit.test("wrapKey rejects with InvalidAccessError when the wrapping key lacks 'wrapKey' usage", function(assert) {
    var done = assert.async();

    Promise.all([
        // wrapping key can encrypt/decrypt but is NOT allowed to wrapKey
        subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"]),
        subtle.generateKey({ name: "AES-CBC", length: 128 }, true, ["encrypt", "decrypt"])
    ])
        .then(function(keys) {
            var wrappingKey = keys[0];
            var keyToWrap = keys[1];
            return subtle.wrapKey("raw", keyToWrap, wrappingKey,
                { name: "AES-CBC", iv: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] });
        })
        .then(function() {
            assert.ok(false, "wrapKey with a key lacking 'wrapKey' usage should reject");
            done();
        })
        // tslint:disable-next-line: no-string-literal
        ["catch"](function(err) {
            assert.equal(err && err.name, "InvalidAccessError", "wrapKey rejects with InvalidAccessError");
            done();
        });
});

QUnit.test("importing a malformed EC point rejects with DataError", function(assert) {
    // 65 bytes that are not a valid uncompressed P-256 point (leading byte != 4).
    var badPoint = [];
    for (var i = 0; i < 65; i += 1) { badPoint.push(i); }

    assertRejectsWith(assert, subtle.importKey("raw", badPoint, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]),
        "DataError", "importKey of a malformed EC point");
});

QUnit.test("getRandomValues throws QuotaExceededError past 65,536 bytes", function(assert) {
    // Fall back to a regular Array where TypedArrays are unavailable (e.g. IE8);
    // getRandomValues enforces the quota on the array's length either way.
    var oversized = (typeof Uint8Array !== "undefined") ? new Uint8Array(65537) : new Array(65537);

    assert.throws(
        function() { msrCrypto.getRandomValues(oversized); },
        function(err) {
            return err && err.name === "QuotaExceededError" &&
                (typeof DOMException === "undefined" || err instanceof DOMException);
        },
        "an oversized array throws QuotaExceededError");
});

QUnit.test("getRandomValues throws TypeMismatchError for floating-point arrays", function(assert) {
    if (typeof Float32Array === "undefined") {
        assert.ok(true, "TypedArrays not supported - skipped");
        return;
    }

    assert.throws(
        function() { msrCrypto.getRandomValues(new Float32Array(4)); },
        function(err) {
            return err && err.name === "TypeMismatchError" &&
                (typeof DOMException === "undefined" || err instanceof DOMException);
        },
        "a floating-point typed array throws TypeMismatchError");
});

QUnit.test("getRandomValues fills and returns the same array for valid input", function(assert) {
    // Where TypedArrays are unavailable (e.g. IE8) getRandomValues accepts and
    // returns a regular Array instead.
    var array = (typeof Uint8Array !== "undefined") ? new Uint8Array(16) : new Array(16);
    var result = msrCrypto.getRandomValues(array);

    assert.strictEqual(result, array, "returns the same array instance that was passed in");

    var nonZero = false;
    for (var i = 0; i < array.length; i += 1) {
        if (array[i] !== 0) { nonZero = true; break; }
    }
    assert.ok(nonZero, "the array was populated with random values");
});
