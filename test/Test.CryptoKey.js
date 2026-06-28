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

QUnit.module("CryptoKey");

QUnit.test("CryptoKey constructor is exposed at the library root", function(assert) {
    assert.equal(typeof msrCrypto.CryptoKey, "function", "msrCrypto.CryptoKey should be a function");
});

QUnit.test("CryptoKey is not directly constructible", function(assert) {
    assert.throws(
        function() { return new msrCrypto.CryptoKey(); },
        /Illegal constructor/,
        "calling 'new CryptoKey()' should throw 'Illegal constructor'");
});

QUnit.test("generateKey returns CryptoKey instances", function(assert) {
    var done = assert.async();

    subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
        .then(function(key) {
            assert.ok(key instanceof msrCrypto.CryptoKey, "secret key is an instance of CryptoKey");
            return subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        })
        .then(function(keyPair) {
            assert.ok(keyPair.publicKey instanceof msrCrypto.CryptoKey, "public key is an instance of CryptoKey");
            assert.ok(keyPair.privateKey instanceof msrCrypto.CryptoKey, "private key is an instance of CryptoKey");
            done();
        })
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](function(error) {
            assert.ok(false, error ? error.toString() : "unexpected error");
            done();
        });
});

QUnit.test("importKey returns a CryptoKey", function(assert) {
    var done = assert.async();

    var rawKey = msrCrypto.fromBase64("AAECAwQFBgcICQoLDA0ODw==");

    subtle.importKey("raw", rawKey, { name: "AES-GCM" }, true, ["encrypt", "decrypt"])
        .then(function(key) {
            assert.ok(key instanceof msrCrypto.CryptoKey, "imported key is an instance of CryptoKey");
            done();
        })
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](function(error) {
            assert.ok(false, error ? error.toString() : "unexpected error");
            done();
        });
});

QUnit.test("CryptoKey exposes only metadata and no key material", function(assert) {
    var done = assert.async();

    subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
        .then(function(keyPair) {
            var privateKey = keyPair.privateKey;

            assert.equal(privateKey.type, "private", "type attribute is exposed");
            assert.equal(privateKey.extractable, true, "extractable attribute is exposed");
            assert.equal(privateKey.algorithm.name, "ECDSA", "algorithm attribute is exposed");
            assert.deepEqual(privateKey.usages, ["sign"], "usages attribute is exposed");

            // Secret material must not be stored on the CryptoKey itself.
            assert.equal(privateKey.d, undefined, "private scalar 'd' is not on the CryptoKey");
            assert.equal(privateKey.keyData, undefined, "keyData is not on the CryptoKey");

            done();
        })
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](function(error) {
            assert.ok(false, error ? error.toString() : "unexpected error");
            done();
        });
});

QUnit.test("a returned CryptoKey can be used in a subsequent operation", function(assert) {
    var done = assert.async();

    var data = [1, 2, 3, 4, 5];

    subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign", "verify"])
        .then(function(key) {
            return subtle.sign({ name: "HMAC" }, key, data)
                .then(function(signature) {
                    return subtle.verify({ name: "HMAC" }, key, testShared.toArray(signature), data);
                });
        })
        .then(function(isValid) {
            assert.ok(isValid, "sign/verify using the returned CryptoKey succeeds");
            done();
        })
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](function(error) {
            assert.ok(false, error ? error.toString() : "unexpected error");
            done();
        });
});
