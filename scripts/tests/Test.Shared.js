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

// Various utilities used by the tests

var utils = msrcryptoUtilities;

var nativeCrypto = window.crypto || window.mscrypto;

// var aes192KeySupport = true;
// var keyOpsExport = true;

// // set 192 key support flag
// nativeCrypto.subtle.generateKey({
//     name: "AES-CBC",
//     length: 192
// }, true, ["encrypt"]).catch(function() {
//     aes192KeySupport = false;
// });

function slowTest() {

    if (skipSlowTests) {
        return QUnit.skip.apply(null, arguments);
    }

    QUnit.test.apply(null, arguments);

}

// Microsoft Edges does not export key_ops or alg properties
// unless keyImport included those properties
// So, generateKey will be missing key_ops & alg
// This will check if this is happening
// crypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt"])
//     .then(function(key) {
//         return crypto.subtle.exportKey("jwk", key);
//     })
//     .then(function(jwkKey) {
//         if (jwkKey.key_ops === void 0) {
//             keyOpsExport = false;
//         }
//     });

var UseNative = false;
var useWebWorkers = false;
var iterations = 10;
var skipSlowTests = true;
var subtle = (UseNative && nativeCrypto) ? crypto.subtle : msrCrypto.subtle;
var label = UseNative ? "(native)" : useWebWorkers ? "msrCrypto (workers)" : "msrCrypto";
var VERIFY = "verify";
var SIGN = "sign";
var ENCRYPT = "encrypt";
var DECRYPT = "decrypt";

msrCrypto.useWebWorkers(useWebWorkers);

var hashLengths = {
    "SHA-1": 20,
    "SHA-224": 28,
    "SHA-256": 32,
    "SHA-384": 48,
    "SHA-512": 64
};

function normalizeRsaKey(keyJwk) {
    keyJwk.d = normalize(keyJwk.d);
}

function normalize(base64url) {
    var data = msrCrypto.fromBase64(base64url);
    while (data.length % 8 > 0) {
        data.unshift(0);
    }
    return msrCrypto.toBase64(data, true);
}

var testShared = {

    // These tests run on systems that may or may not support TypedArrays.
    // These tests may run using the native web crypto api - that require TypedArrays.
    // MsrCrypto may use regular Arrays or TypedArrays
    // This function will allow our tests code to uses regular Arrays.
    // It will convert Arrays to TypedArrays when a global 'UseNative' is set.
    // This will also convert base64 & base64url to an array
    // It will randomly convert Arrays and ArrayBuffers to Arrays and TypedArrays
    // when using MsrCrypto.
    arr: function (array /* may be Array or ArrayBuffer */) {

        if (validation.isBase64(array) || validation.isBase64Url(array) || array === "") {
            array = msrCrypto.fromBase64(array);
        }

        if (typeof Uint8Array === "undefined") {
            // TypedArrays not supported, so our array must be a regular Array
            return array;
        }

        // if using the native web-crypto-api, convert this to a TypedArray always.
        if (UseNative === true) {
            return new Uint8Array(array);
        }

        if (array instanceof ArrayBuffer) {
            array = new Uint8Array(array);
        }

        if (Math.random() > 0.5 /* 50% */) {
            // return Uint8Array
            return array instanceof Uint8Array ? array : new Uint8Array(array);
        }

        // return regular Array (Array.apply only supports a limited length)
        return testShared.toArray(array);
    },

    clone: function (obj) {
        //return JSON.parse(JSON.stringify(obj));
        return utils.clone(obj);
    },

    // converts array/arrayBuffer to a regular array
    toArray: function (arrayLike) {

        if (typeof Uint8Array === "undefined") {
            // TypedArrays not supported, so our array must be a regular Array
            return arrayLike;
        }

        if (arrayLike instanceof Array) { return arrayLike; }

        if (arrayLike instanceof ArrayBuffer) {
            arrayLike = new Uint8Array(arrayLike);
        }

        return arrayLike instanceof Uint8Array ? arrayLike.length === 1 ? [arrayLike[0]] : Array.apply(null, arrayLike) : arrayLike;
    },

    getRandomBytes: function (min, max, mod) {
        var bytes;

        max = max || min;

        var len = Math.floor(Math.random() * (++max - min)) + min;

        if(mod) {
            len = len - len % mod;
            if(len < min) len += mod;
        }

        if (nativeCrypto) {
            bytes = new Uint8Array(len);
            nativeCrypto.getRandomValues(bytes);
            return bytes.length === 1 ? [bytes[0]] : Array.apply(null, bytes);
        }

        bytes = new Array(len);
        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = Math.floor(Math.random() * 256);
        }

        return bytes;
    },

    chance: function (percent) {
        return Math.random() < percent;
    },

    compareUsages: function (usage1, usage2) {

        if (usage1.length !== usage2.length) {
            return false;
        }

        for (var u = 0; u < usage1.length; u++) {
            var found = false;
            for (var k = 0; k < usage2.length; k++) {
                if (usage2[k] === usage1[u]) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }

        return true;
    },

    getPublicUsage: function (usages) {
        var publicUsages = [];
        for (var i = 0; i < usages.length; i++) {
            if (usages[i].toUpperCase() === "VERIFY") { publicUsages.push("verify"); }
            if (usages[i].toUpperCase() === "ENCRYPT") { publicUsages.push("encrypt"); }
        }
        return publicUsages;
    },

    getPrivateUsage: function (usages) {
        var privateUsages = [];
        for (var i = 0; i < usages.length; i++) {
            var use = usages[i].toUpperCase();
            if (use === "SIGN") { privateUsages.push(use.toLowerCase()); }
            if (use === "DECRYPT") { privateUsages.push(use.toLowerCase()); }
            if (use === "DERIVEBITS") { privateUsages.push("deriveBits"); }
            if (use === "DERIVEKEY") { privateUsages.push("deriveKey"); }
        }
        return privateUsages;
    },

    isBytes: utils.isBytes,

    testContext: function (numIterations, assert) {
        return {   // test context
            assert: assert,
            count: numIterations,
            done: assert.async(),
            leftToRun: numIterations
        };
    },

    maxMessageLen: function (keyAlgorithm) {

        if (keyAlgorithm.modulusLength) {
            if (keyAlgorithm.name === "RSA-OAEP") {
                return (keyAlgorithm.modulusLength / 8) - 2 * hashLengths[keyAlgorithm.hash.name] - 2;
            }
            if (keyAlgorithm.name === "RSAES-PKCS1-V1_5") {
                return (keyAlgorithm.modulusLength / 8) - 11;
            }
            throw new Error("unknown algorithm.");
        }

        return 1000;
    },

    keyImportExportTestSpki: function (vectorSet, usages, keyValidationFunc, context) {

        // spki tests have a public key in spki format and a verify key in jwk format
        // The spki key is imported, then exported as jwk and compared against the jwk verify key.

        var format = vectorSet.format;
        var vector = vectorSet.vectors[(context.count - 1) % vectorSet.vectors.length];
        var usage = vector.verify.key_ops;
        var algorithm = vectorSet.algorithm;
        var keyData = testShared.arr(msrCrypto.fromBase64(vector.publicKey || vector.privateKey));

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.keyImportExportTestSpki(vectorSet, usages, keyValidationFunc, context);
        }

        return subtle.importKey(format, keyData, algorithm, true, usage)
            .then(exportKey)
            .then(validateKey)
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function exportKey(cryptoKey) {
            return Promise.all([
                subtle.exportKey("jwk", cryptoKey),
                subtle.exportKey(format, cryptoKey)
            ]);
        }

        function validateKey(actualKeys) {
            context.assert.propEqual(actualKeys[0], vector.verify, JSON.stringify(actualKeys[0]));
            context.assert.propEqual(utils.toBase64(actualKeys[1]), vector.publicKey || vector.privateKey, utils.toBase64(actualKeys[1]));
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

    },

    keyImportExportTest: function (vectorSet, usages, keyValidationFunc, context) {

        var format = vectorSet.format;
        var vector = vectorSet.vectors[(context.count - 1) % vectorSet.vectors.length];
        var usage = vector.key_ops || (vector.verify && vector.verify.key_ops) || usages[(context.count - 1) % usages.length] || []; // cycle through possible usages
        var algorithm = vectorSet.algorithm;
        var keyData = format !== "jwk" ? testShared.arr(msrCrypto.fromBase64(vector)) : vector;

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.keyImportExportTest(vectorSet, usages, keyValidationFunc, context);
        }

        return subtle.importKey(format, keyData, algorithm, true, usage)
            .then(exportKey)
            .then(validateKey)
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function exportKey(cryptoKey) {
            if (vector.verify) { // export spki key as jwk for validation
                return subtle.exportKey("jwk", cryptoKey);
            }
            return subtle.exportKey(format, cryptoKey);
        }

        function validateKey(exportedKey) {

            //if ( keyData.key_ops ) { keyData.key_ops = usage; } // set expected key_ops on the expected-key

            //keyValidationFunc( exportedKey, keyData, context.assert );

            var actualKey = format === "raw" ? testShared.toArray(exportedKey) : exportedKey;

            // if a verify key is specified, use it (for spki we use a jwk key to verify the export)
            var startingKey = vector.verify || testShared.toArray(keyData);

            context.assert.deepEqual(actualKey, startingKey, JSON.stringify(actualKey));

            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

    },

    keyPairImportExportTest: function (vectorSet, usages, keyValidationFunc, context) {

        var format = vectorSet.format;
        var algorithm = vectorSet.algorithm;
        var vector = vectorSet.vectors[(context.count - 1) % vectorSet.vectors.length];

        if (--context.count > 0) { // recursively call to start the next iteration
            this.keyPairImportExportTest(vectorSet, usages, keyValidationFunc, context);
        }

        return Promise.all([
            subtle.importKey(vectorSet.format, vector.publicKey, algorithm, true, vector.publicKey.key_ops),
            subtle.importKey(vectorSet.format, vector.privateKey, algorithm, true, vector.privateKey.key_ops)
        ])
            .then(exportKeyPair)
            .then(validateKeyPair)
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function exportKeyPair(keyPairArray) {
            return Promise.all([
                subtle.exportKey(format, keyPairArray[0] /*public*/),
                subtle.exportKey(format, keyPairArray[1] /*private*/)
            ]);
        }

        function validateKeyPair(exportKeyArray) {
            // keyValidationFunc( exportKeyArray[0] /*public*/, vector.publicKey );
            // keyValidationFunc( exportKeyArray[1] /*private*/, vector.privateKey );
            var actualKey = format === "raw" ? testShared.toArray(exportKeyArray[0]) : exportKeyArray[0];
            context.assert.deepEqual(
                vector.publicKey, testShared.toArray(vector.publicKey), JSON.stringify(actualKey));

            actualKey = format === "raw" ? testShared.toArray(exportKeyArray[1]) : exportKeyArray[1];
            context.assert.deepEqual(
                vector.privateKey, testShared.toArray(vector.privateKey), JSON.stringify(actualKey));

            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

    },

    keyGenerateTest: function (algorithm, usages, keyValidationFunc, context) {

        var usage = usages[(context.count - 1) % usages.length]; // cycle through possible usages

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.keyGenerateTest(algorithm, usages, keyValidationFunc, context);
        }

        return subtle.generateKey(algorithm, true, usage)
            .then(exportKey)
            .then(validateKey)
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function exportKey(cryptoKey) {
            return subtle.exportKey("jwk", cryptoKey);
        }

        function validateKey(exportedKey) {
            var reason = { message: undefined };
            context.assert.ok(keyValidationFunc(exportedKey, algorithm, usage, reason),
                reason.message || JSON.stringify(exportedKey));
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }
    },

    keyGeneratePairTest: function (algorithm, usages, keyValidationFunc, context) {

        //var usage = usages[(context.count-1) % usages.length]; // cycle through possible usages
        var reason = { message: undefined };

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.keyGeneratePairTest(algorithm, usages, keyValidationFunc, context);
        }

        return subtle.generateKey(algorithm, true, usages)
            .then(exportKeyPair)
            .then(validateKeyPair)
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function exportKeyPair(keyPair) {
            return Promise.all([
                subtle.exportKey("jwk", keyPair.publicKey),
                subtle.exportKey("jwk", keyPair.privateKey)
            ]);
        }

        function validateKeyPair(exportedKeyPair /*[0]=public, [1]=private*/) {
            context.assert.ok(
                keyValidationFunc.public(exportedKeyPair[0], algorithm, testShared.getPublicUsage(usages), reason),
                reason.message || JSON.stringify(exportedKeyPair[0]));

            reason.message = undefined;
            context.assert.ok(
                keyValidationFunc.private(exportedKeyPair[1], algorithm, testShared.getPrivateUsage(usages), reason),
                reason.message || JSON.stringify(exportedKeyPair[1]));

            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }
    },

    encryptDecryptTest: function (keyAlg, encryptAlg, context) {

        // alg params may be alg-generating functions or a static algorithm objects
        var encAlgorithm = typeof encryptAlg === "function" ? encryptAlg(context.count) : encryptAlg;
        var keyAlgorithm = typeof keyAlg === "function" ? keyAlg(context.count) : keyAlg;
        var maxMessageLen = testShared.maxMessageLen(keyAlg);
        var plainText = testShared.getRandomBytes(1, maxMessageLen, keyAlg.name === "AES-KW" ? 8 : undefined );
        var cryptoKeyEncrypt;
        var cryptoKeyDecrypt;

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.encryptDecryptTest(keyAlg, encryptAlg, context);
        }

        return subtle.generateKey(keyAlgorithm, true, ["encrypt", "decrypt"])
            .then(encrypt)
            .then(decrypt)
            .then(validate)
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function encrypt(cryptoKeyOut) {
            cryptoKeyEncrypt = (cryptoKeyOut.publicKey) ? cryptoKeyOut.publicKey : cryptoKeyOut;
            cryptoKeyDecrypt = (cryptoKeyOut.privateKey) ? cryptoKeyOut.privateKey : cryptoKeyOut;
            return subtle.encrypt(encAlgorithm, cryptoKeyEncrypt, testShared.arr(plainText));
        }

        function decrypt(cipherBytesOut) {
            return subtle.decrypt(encAlgorithm, cryptoKeyDecrypt, testShared.arr(cipherBytesOut));
        }

        function validate(plainTextOut) {

            var plainTextEnd = testShared.toArray(plainTextOut);
            var outputMsg = plainText.join() + "===" + plainTextEnd.join();

            context.assert.deepEqual(plainText, plainTextEnd, outputMsg);

            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }
    },

    signVerifyTest: function (keyAlg, signAlg, context) {

        // alg params may be alg-generating functions or a static algorithm objects
        var signAlgorithm = typeof signAlg === "function" ? signAlg(context.count) : signAlg;
        var keyAlgorithm = typeof keyAlg === "function" ? keyAlg(context.count) : keyAlg;
        var maxMessageLen = keyAlgorithm.modulusLength ?
            keyAlgorithm.modulusLength / 8 - 2 * hashLengths[keyAlgorithm.hash.name] - 2 : 1000;
        var plainText = testShared.getRandomBytes(1, maxMessageLen);
        var cryptoKeySign;
        var cryptoKeyVerify;
        var signature;

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.signVerifyTest(keyAlg, signAlg, context);
        }

        return subtle.generateKey(keyAlgorithm, true, ["sign", "verify"])
            .then(sign)
            .then(verify)
            .then(validate)
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function sign(keyPair) {
            cryptoKeyVerify = (keyPair.publicKey) ? keyPair.publicKey : keyPair;
            cryptoKeySign = (keyPair.privateKey) ? keyPair.privateKey : keyPair;
            return subtle.sign(signAlgorithm, cryptoKeySign, testShared.arr(plainText));
        }

        function verify(signatureOut) {
            signature = signatureOut;
            return subtle.verify(
                signAlgorithm, cryptoKeyVerify, testShared.arr(signatureOut), testShared.arr(plainText));
        }

        function validate(verified) {
            context.assert.ok(verified, "signature verified : " + testShared.toArray(signature).join());
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }
    },

    verifyNativeSignatureTest: function (signAlgorithm, vectorSet, context) {

        var vector = vectorSet.vectors[(context.count - 1) % vectorSet.vectors.length];
        var signature = testShared.arr(vector.signature);
        var plainText = testShared.arr(vector.plainText);
        var algorithm = typeof signAlgorithm === "function" ?
            signAlgorithm(context.count) : this.clone(signAlgorithm);

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.verifyNativeSignatureTest(signAlgorithm, vectorSet, context);
        }

        subtle.importKey(vectorSet.format, vector.publicKey || vector.key, vectorSet.algorithm, true, [VERIFY])
            .then(verify)
            .then(validate)
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function verify(cryptoKey) {
            if (algorithm.saltLength !== void 0) { algorithm.saltLength = vector.saltLength; }
            return subtle.verify(algorithm, cryptoKey, signature, plainText);
        }

        function validate(verified) {
            context.assert.ok(verified, "signature verified : " + msrCrypto.toBase64(signature));
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

    },

    decryptNativeCiphersTest: function (vectorSet, context) {

        var encryptAlgorithm = this.clone(vectorSet.algorithm);
        //if(encryptAlgorithm.publicExponent ? encryptAlgorithm.publicExponent = testShared.arr( encryptAlgorithm.publicExponent)
        var vector = vectorSet.vectors[(context.count - 1) % vectorSet.vectors.length];
        var cipherText = testShared.arr(vector.cipherText);
        var plainText = testShared.arr(vector.plainText);
        encryptAlgorithm = typeof encryptAlgorithm === "function" ? encryptAlgorithm(context.count) : encryptAlgorithm;

        var params = vector.params;
        if (params) {
            for (var propName in params) {
                if (params.hasOwnProperty(propName)) {
                    // assumes a string is base64 data
                    var value = params[propName];
                    encryptAlgorithm[propName] = (typeof value === "string") ? testShared.arr(value) : value;
                }
            }
        }

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.decryptNativeCiphersTest(vectorSet, context);
        }

        subtle.importKey(vectorSet.format, vector.privateKey || (vectorSet.format === 'jwk' ? vector.key : testShared.arr(vector.key)), vectorSet.algorithm, true, [DECRYPT])
            .then(decrypt)
            .then(validate)
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function decrypt(cryptoKey) {
            return subtle.decrypt(encryptAlgorithm, cryptoKey, cipherText);
        }

        function validate(plainTextOut) {
            context.assert.deepEqual(
                testShared.toArray(plainTextOut), testShared.toArray(plainText), msrCrypto.toBase64(plainTextOut));
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

    },

    deriveKeyTest: function (vectorSet, keyValidationFunc, context) {

        var vector = vectorSet.vectors[(context.count) % vectorSet.vectors.length];

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.deriveKeyTest(vectorSet, keyValidationFunc, context);
        }

        var keyPromises;

        if (vector.privateKey && vector.publicKey) {
            keyPromises = [
                subtle.importKey("jwk", vector.publicKey, vectorSet.algorithm, true, []),
                subtle.importKey("jwk", vector.privateKey, vectorSet.algorithm, true, ["deriveKey"])
            ];
        } else {
            keyPromises = [  // for now this will always be pbkdf2 until we add additional algorithms.
                subtle.importKey("raw", msrCrypto.fromBase64(vector.params.key || vector.params.password), vectorSet.algorithm, false, ["deriveKey"])
            ];
        }

        return Promise.all(keyPromises)
            .then(deriveKey)
            .then(exportKey)
            .then(validateKey)
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function deriveKey(keys) {
            if (keys.length > 1) { //ecdh
                vectorSet.algorithm.public = keys[0];
                return subtle.deriveKey(vectorSet.algorithm, keys[1], vectorSet.derivedKeyAlg, true, ["encrypt", "decrypt"]);

            } else if (vector.params.algorithm.name === 'PBKDF2') {
                vector.params.algorithm.salt = msrCrypto.fromBase64(vector.params.algorithm.salt);
                return subtle.deriveKey(vector.params.algorithm, keys[0], vectorSet.derivedKeyAlg, true, vector.derivedKey.key_ops);

            } else if (vector.params.algorithm.name === 'HKDF') {
                vector.params.algorithm.salt = msrCrypto.fromBase64(vector.params.algorithm.salt);
                vector.params.algorithm.info = msrCrypto.fromBase64(vector.params.algorithm.info);
                return subtle.deriveKey(vector.params.algorithm, keys[0], vectorSet.derivedKeyAlg, true, vector.derivedKey.key_ops);

            } else if (vector.params.algorithm.name === 'CONCAT') {
                return subtle.deriveKey(vector.params.algorithm, keys[0], vectorSet.derivedKeyAlg, true, vector.derivedKey.key_ops);

            } else if (vector.params.algorithm.name === 'HKDF-CTR') {
                vector.params.algorithm.context = msrCrypto.fromBase64(vector.params.algorithm.context);
                vector.params.algorithm.label = msrCrypto.fromBase64(vector.params.algorithm.label);
                return subtle.deriveKey(vector.params.algorithm, keys[0], vectorSet.derivedKeyAlg, true, vector.derivedKey.key_ops);
            }
        }

        function exportKey(derivedKey) {
            return subtle.exportKey("jwk", derivedKey);
        }

        function validateKey(exportedKey) {
            context.assert.propEqual(exportedKey, vector.derivedKey, JSON.stringify(exportedKey));
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }
    },

    deriveBitsTest: function (vectorSet, context) {

        var vector = vectorSet.vectors[(context.count - 1) % vectorSet.vectors.length];

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.deriveBitsTest(vectorSet, context);
        }

        var keyPromises;

        if (vector.privateKey && vector.publicKey) {
            keyPromises = [
                subtle.importKey("jwk", vector.publicKey, vectorSet.algorithm, true, []),
                subtle.importKey("jwk", vector.privateKey, vectorSet.algorithm, true, ["deriveKey"])
            ];
        } else {
            keyPromises = [  // for now this will always be pbkdf2 until we add additional algorithms.
                subtle.importKey("raw", msrCrypto.fromBase64(vector.params.key != null ? vector.params.key : vector.params.password), vectorSet.algorithm, false, ["deriveKey"])
            ];
        }

        return Promise.all(keyPromises)
            .then(derivedBits)
            .then(validateBits)
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function derivedBits(keys) {

            if (keys.length > 1) { //ecdh
                vectorSet.algorithm.public = keys[0];
                return subtle.deriveBits(vectorSet.algorithm, keys[1], vector.bits);

            } else if (vector.params.algorithm.name === 'PBKDF2') {
                vector.params.algorithm.salt = msrCrypto.fromBase64(vector.params.algorithm.salt);
                return subtle.deriveBits(vector.params.algorithm, keys[0], vector.bits);

            } else if (vector.params.algorithm.name === 'HKDF') {
                vector.params.algorithm.salt = msrCrypto.fromBase64(vector.params.algorithm.salt);
                vector.params.algorithm.info = msrCrypto.fromBase64(vector.params.algorithm.info);
                return subtle.deriveBits(vector.params.algorithm, keys[0], vector.bits);

            } else if (vector.params.algorithm.name === 'CONCAT') {
                return subtle.deriveBits(vector.params.algorithm, keys[0], vector.bits);

            } else if (vector.params.algorithm.name === 'HKDF-CTR') {
                vector.params.algorithm.context = msrCrypto.fromBase64(vector.params.algorithm.context);
                vector.params.algorithm.label = msrCrypto.fromBase64(vector.params.algorithm.label);
                return subtle.deriveBits(vector.params.algorithm, keys[0], vector.bits);
            }
        }

        function validateBits(bits) {
            context.assert.deepEqual(
                testShared.toArray(bits), msrCrypto.fromBase64(vector.derivedBits), msrCrypto.toBase64(bits));
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
        }
    },

    hashTest: function (vectorSet, context) {

        var vector = vectorSet.vectors[context.count - 1 % vectorSet.vectors.length];

        if (--context.count > 0) { // recursively call to start the next iteration
            testShared.hashTest(vectorSet, context);
        }

        return subtle.digest(vectorSet.algorithm, testShared.arr(msrCrypto.fromBase64(vector.data)))
            .then(validateHash)
        // IE8 will not allow .catch()
        // tslint:disable-next-line: no-string-literal
        ["catch"](fail); // any errors above will get handled here

        function validateHash(hash) {
            context.assert.deepEqual(
                testShared.toArray(hash), msrCrypto.fromBase64(vector.hash), testShared.toArray(hash).join(","));
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }

        function fail(error) {
            context.assert.ok(false, error ? error.toString() : "unexpected error");
            if (--context.leftToRun === 0) { context.done(); } // call done() if the final test iteration
        }
    }
};

// function testContext( iterations, assert ) {
//     return {   // test context
//         assert: assert,
//         count: iterations,
//         done: assert.async(),
//         leftToRun: iterations
//     };
// }

QUnit.conditional = function (condition, message, callback) {

    if (condition) {
        QUnit.test(message, callback);
    } else {
        QUnit.skip(message, callback);
    }
};

var validation = {
    isString: function (text, value /*optional*/, caseSensitive /*optional*/) {

        if (typeof text !== "string") {
            return false;
        }

        if (value !== void 0) {

            // if value is string, verify text matches
            if (typeof value === "string") {
                return caseSensitive ? value === text : value.toUpperCase() === text.toUpperCase();
            }

            // if value is RegExp, verify text matches RegExp
            if (value instanceof RegExp && value.test(text)) {
                return true;
            }

            return false;
        }

        return true;
    },

    isBoolean: function (text, value /*optional*/) {

        if (typeof text !== "boolean") {
            return false;
        }

        if (value !== void 0) {
            if (typeof value !== "boolean") {
                return false;
            }

            if (value !== text) {
                return false;
            }
        }

        return true;
    },

    isBase64Url: function (text, lengthMin /*optional*/, lengthMax /*optional*/) {
        if (!validation.isString(text, /^([A-Za-z0-9-_]+)$/)) { return false; }
        if (lengthMin) {
            var bytes = utils.fromBase64(text);
            if (bytes.length > lengthMax || bytes.length < lengthMin) { return false; }
        }
        return true;
    },

    isBase64: function (text, lengthMin /*optional*/, lengthMax /*optional*/) {
        if (!validation.isString(text, /^([A-Za-z0-9+\/=]+)$/)) { return false; }
        if (lengthMin) {
            var bytes = utils.fromBase64(text);
            if (bytes.length > lengthMax || bytes.length < lengthMin) { return false; }
        }
        return true;
    },

    isBytes: utils.isBytes,

    prop: {
        isBase64Url: function (obj, prop, lengthMin /*optional*/, lengthMax /*optional*/) {
            if (obj[prop] == null) { return false; }
            return validation.isBase64Url(obj[prop], lengthMin, lengthMax);
        },
        string: function (obj, prop, value /*optional*/) {
            if (obj[prop] == null) { return false; }
            return validation.isString(obj[prop], value);
        },
        boolean: function (obj, prop, value /*optional*/) {
            if (obj[prop] == null) { return false; }
            return validation.isBoolean(obj[prop], value);
        }
    }

};
