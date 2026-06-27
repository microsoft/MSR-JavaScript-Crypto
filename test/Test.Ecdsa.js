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

// We want these tests run 3 separate times:
//
//  1. with default msrCrypto
//  2. msrCrypto with web-workers enabled (if available)
//  3. native crypto (if available)
//
// We cannot call the tests and then change the mode because of the async nature of the tests
// We need a way to know when all the tests of the set have completed, before we start the next set

"use strict";

ecdsaTests();

function ecdsaTests() {

    QUnit.module("ECDSA");

    var ts = testShared;
    var context = ts.testContext;

    var ecdsaUsages = {
        public: [[VERIFY]],
        private: [[SIGN]]
    };

    QUnit.test( label + " verify native signature P-256 Sha-1 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-1" ), ecdsa.p256.sha1.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-256 Sha-256 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-256" ), ecdsa.p256.sha256.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-256 Sha-384 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-384" ), ecdsa.p256.sha384.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-256 Sha-512 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-512" ), ecdsa.p256.sha512.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-384 Sha-1 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-1" ), ecdsa.p384.sha1.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-384 Sha-256 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-256" ), ecdsa.p384.sha256.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-384 Sha-384 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-384" ), ecdsa.p384.sha384.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-384 Sha-512 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-512" ), ecdsa.p384.sha512.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-521 Sha-1 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-1" ), ecdsa.p521.sha1.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-521 Sha-256 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-256" ), ecdsa.p521.sha256.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-521 Sha-384 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-384" ), ecdsa.p521.sha384.signatures, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature P-521 Sha-512 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            ecdsaSignAlg( "SHA-512" ), ecdsa.p521.sha512.signatures, context( iterations, assert ) );
    } );

    // ===========================================================================================================

    QUnit.test( label + " key import/export jwk P-256", function( assert ) {
        ts.keyPairImportExportTest( ecdsa.p256.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export jwk P-384", function( assert ) {
        ts.keyPairImportExportTest( ecdsa.p384.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export jwk P-521", function( assert ) {
        ts.keyPairImportExportTest( ecdsa.p521.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import jwk re-pads leading-zero-trimmed P-256", function( assert ) {
        // Regression: a private 'd' (and x/y) supplied with leading zeros trimmed
        // must be accepted on import and re-padded to the full curve element
        // length on export (32 bytes for P-256), matching Chrome/Chromium.
        var vector = ecdsa.p256.jwkTrimmed;
        var expected = vector.expectedPrivateKey;
        var elementLength = vector.elementLength;
        var done = assert.async();

        subtle.importKey( "jwk", vector.trimmedPrivateKey, vector.algorithm, true, vector.trimmedPrivateKey.key_ops )
            .then( function( key ) {
                return subtle.exportKey( "jwk", key );
            } )
            .then( function( jwk ) {
                assert.equal( msrCrypto.fromBase64( jwk.d ).length, elementLength, "exported 'd' is full curve length" );
                assert.equal( msrCrypto.fromBase64( jwk.x ).length, elementLength, "exported 'x' is full curve length" );
                assert.equal( msrCrypto.fromBase64( jwk.y ).length, elementLength, "exported 'y' is full curve length" );
                assert.equal( jwk.d, expected.d, "exported 'd' matches the zero-padded value" );
                assert.equal( jwk.x, expected.x, "exported 'x' matches the zero-padded value" );
                assert.equal( jwk.y, expected.y, "exported 'y' matches the zero-padded value" );
                done();
            } )
            // IE8 will not allow .catch()
            // tslint:disable-next-line: no-string-literal
            ["catch"]( function( error ) {
                assert.ok( false, error ? error.toString() : "unexpected error" );
                done();
            } );
    } );



    QUnit.test(label + " key import/export spki P-256 ", function(assert) {
        ts.keyImportExportTestSpki(ecdsa.p256.spki, ecdsaUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export spki P-384 ", function(assert) {
        ts.keyImportExportTestSpki(ecdsa.p384.spki, ecdsaUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export spki P-521 ", function(assert) {
        ts.keyImportExportTestSpki(ecdsa.p521.spki, ecdsaUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export pkcs8 P-256 ", function(assert) {
        ts.keyImportExportTestSpki(ecdsa.p256.pkcs8, ecdsaUsages.private, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export pkcs8 P-384 ", function(assert) {
        ts.keyImportExportTestSpki(ecdsa.p384.pkcs8, ecdsaUsages.private, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export pkcs8 P-521 ", function(assert) {
        ts.keyImportExportTestSpki(ecdsa.p521.pkcs8, ecdsaUsages.private, undefined, context(iterations, assert));
    });




    QUnit.test( label + " key import/export raw P-256", function( assert ) {
        ts.keyImportExportTest( ecdsa.p256.raw, ecdsaUsages.public, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export raw P-384", function( assert ) {
        ts.keyImportExportTest( ecdsa.p384.raw, ecdsaUsages.public, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export raw P-521", function( assert ) {
        ts.keyImportExportTest( ecdsa.p521.raw, ecdsaUsages.public, undefined, context( iterations, assert ) );
    } );

    QUnit.test(label + " key import/export jwk NUMSP256D1 ", function(assert) {
        ts.keyPairImportExportTest(ecdsa.numsp256d1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP384D1 ", function(assert) {
        ts.keyPairImportExportTest(ecdsa.numsp384d1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP512D1 ", function(assert) {
        ts.keyPairImportExportTest(ecdsa.numsp512d1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP256T1 ", function(assert) {
        ts.keyPairImportExportTest(ecdsa.numsp256t1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP384T1 ", function(assert) {
        ts.keyPairImportExportTest(ecdsa.numsp384t1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP512T1 ", function(assert) {
        ts.keyPairImportExportTest(ecdsa.numsp512t1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP256D1 ", function(assert) {
        ts.keyImportExportTest(ecdsa.numsp256d1.raw, ecdsaUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP384D1 ", function(assert) {
        ts.keyImportExportTest(ecdsa.numsp384d1.raw, ecdsaUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP512D1 ", function(assert) {
        ts.keyImportExportTest(ecdsa.numsp512d1.raw, ecdsaUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP256T1 ", function(assert) {
        ts.keyImportExportTest(ecdsa.numsp256t1.raw, ecdsaUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP384T1 ", function(assert) {
        ts.keyImportExportTest(ecdsa.numsp384t1.raw, ecdsaUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP512T1 ", function(assert) {
        ts.keyImportExportTest(ecdsa.numsp512t1.raw, ecdsaUsages.public, undefined, context(iterations, assert));
    });

    // ===========================================================================================================

    QUnit.test( label + " generateKeyTest P-256", function( assert ) {
        ts.keyGeneratePairTest( ecdsaKeyAlg( "P-256" ), [VERIFY, SIGN], inspectEcdsaKey, context( iterations, assert ) );
    } );

    QUnit.test( label + " generateKeyTest P-384", function( assert ) {
        ts.keyGeneratePairTest( ecdsaKeyAlg( "P-384" ), [VERIFY, SIGN], inspectEcdsaKey, context( iterations, assert ) );
    } );

    QUnit.test( label + " generateKeyTest P-521", function( assert ) {
        ts.keyGeneratePairTest( ecdsaKeyAlg( "P-521" ), [VERIFY, SIGN], inspectEcdsaKey, context( iterations, assert ) );
    } );

    QUnit.test(label + " generateKeyTest BN-254", function(assert) {
        ts.keyGeneratePairTest(ecdsaKeyAlg("BN-254"), [VERIFY, SIGN], inspectEcdsaKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP256D1", function(assert) {
        ts.keyGeneratePairTest(ecdsaKeyAlg("NUMSP256D1"), [VERIFY, SIGN], inspectEcdsaKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP384D1", function(assert) {
        ts.keyGeneratePairTest(ecdsaKeyAlg("NUMSP384D1"), [VERIFY, SIGN], inspectEcdsaKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP512D1", function(assert) {
        ts.keyGeneratePairTest(ecdsaKeyAlg("NUMSP512D1"), [VERIFY, SIGN], inspectEcdsaKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP256T1", function(assert) {
        ts.keyGeneratePairTest(ecdsaKeyAlg("NUMSP256T1"), [VERIFY, SIGN], inspectEcdsaKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP384T1", function(assert) {
        ts.keyGeneratePairTest(ecdsaKeyAlg("NUMSP384T1"), [VERIFY, SIGN], inspectEcdsaKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP512T1", function(assert) {
        ts.keyGeneratePairTest(ecdsaKeyAlg("NUMSP512T1"), [VERIFY, SIGN], inspectEcdsaKey, context(iterations, assert));
    });

    // ===========================================================================================================

    QUnit.test( label + " sign/verify P-256 SHA-1", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-256" ), ecdsaSignAlg( "SHA-1" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-256 SHA-256", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-256" ), ecdsaSignAlg( "SHA-256" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-256 SHA-384", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-256" ), ecdsaSignAlg( "SHA-384" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-256 SHA-512", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-256" ), ecdsaSignAlg( "SHA-512" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-384 SHA-1", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-384" ), ecdsaSignAlg( "SHA-1" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-384 SHA-256", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-384" ), ecdsaSignAlg( "SHA-256" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-384 SHA-384", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-384" ), ecdsaSignAlg( "SHA-384" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-384 SHA-512", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-384" ), ecdsaSignAlg( "SHA-512" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-521 SHA-1", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-521" ), ecdsaSignAlg( "SHA-1" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-521 SHA-256", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-521" ), ecdsaSignAlg( "SHA-256" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-521 SHA-384", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-521" ), ecdsaSignAlg( "SHA-384" ), context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify P-521 SHA-512", function( assert ) {
        ts.signVerifyTest( ecdsaKeyAlg( "P-521" ), ecdsaSignAlg( "SHA-512" ), context( iterations, assert ) );
    } );

    QUnit.test(label + " sign/verify NUMSP256D1 SHA-1", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP256D1"), ecdsaSignAlg("SHA-1"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP256D1 SHA-256", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP256D1"), ecdsaSignAlg("SHA-256"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP256D1 SHA-384", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP256D1"), ecdsaSignAlg("SHA-384"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP256D1 SHA-512", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP256D1"), ecdsaSignAlg("SHA-512"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP384D1 SHA-1", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP384D1"), ecdsaSignAlg("SHA-1"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP384D1 SHA-256", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP384D1"), ecdsaSignAlg("SHA-256"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP384D1 SHA-384", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP384D1"), ecdsaSignAlg("SHA-384"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP256D1 SHA-512", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP384D1"), ecdsaSignAlg("SHA-512"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP512D1 SHA-1", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP512D1"), ecdsaSignAlg("SHA-1"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP512D1 SHA-256", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP512D1"), ecdsaSignAlg("SHA-256"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP512D1 SHA-384", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP512D1"), ecdsaSignAlg("SHA-384"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP512D1 SHA-512", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP512D1"), ecdsaSignAlg("SHA-512"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP256T1 SHA-1", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP256T1"), ecdsaSignAlg("SHA-1"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP256T1 SHA-256", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP256T1"), ecdsaSignAlg("SHA-256"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP256T1 SHA-384", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP256T1"), ecdsaSignAlg("SHA-384"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP256T1 SHA-512", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP256T1"), ecdsaSignAlg("SHA-512"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP384T1 SHA-1", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP384T1"), ecdsaSignAlg("SHA-1"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP384T1 SHA-256", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP384T1"), ecdsaSignAlg("SHA-256"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP384T1 SHA-384", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP384T1"), ecdsaSignAlg("SHA-384"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP256T1 SHA-512", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP384T1"), ecdsaSignAlg("SHA-512"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP512T1 SHA-1", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP512T1"), ecdsaSignAlg("SHA-1"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP512T1 SHA-256", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP512T1"), ecdsaSignAlg("SHA-256"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP512T1 SHA-384", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP512T1"), ecdsaSignAlg("SHA-384"), context(iterations, assert));
    });

    QUnit.test(label + " sign/verify NUMSP512T1 SHA-512", function(assert) {
        ts.signVerifyTest(ecdsaKeyAlg("NUMSP512T1"), ecdsaSignAlg("SHA-512"), context(iterations, assert));
    });
}

var ecdsaKeyLengths = {
    "P-256": 32,
    "P-384": 48,
    "P-521": 66,
    "BN-254": 32,
    "NUMSP256D1": 32,
    "NUMSP256T1": 32,
    "NUMSP384D1": 48,
    "NUMSP384T1": 48,
    "NUMSP512D1": 64,
    "NUMSP512T1": 64
};

function ecdsaKeyAlg(curve) {
    return {
        name: "ECDSA",
        namedCurve: curve
    };
}

function ecdsaSignAlg(hashAlg) {
    return {
        name: "ECDSA",
        hash: { name: hashAlg }
    };
}

var inspectEcdsaKey = {
    public: function(keyObj, algorithm, usages, reason) {

        var fail = [];

        var expLenMax = ecdsaKeyLengths[algorithm.namedCurve];
        var expLenMin = expLenMax;

        // has crv property equal to "P-521"
        if (!validation.prop.string(keyObj, "crv", algorithm.namedCurve)) {
            fail.push("key.crv !== " + algorithm.namedCurve);
        }

        // has ext property equal to true
        if (!validation.prop.boolean(keyObj, "ext", true)) {
            fail.push("key.ext !== true");
        }

        // has e property that is base64url
        if (!validation.prop.isBase64Url(keyObj, "x", expLenMin, expLenMax)) {
            fail.push("key.x is not base64url or has incorrect length");
        }

        // has n property that is base64url
        if (!validation.prop.isBase64Url(keyObj, "y", expLenMin, expLenMax)) {
            fail.push("key.y is not base64url or has incorrect length");
        }

        // has key_ops property with expected usages
        if (Object.prototype.toString.call(keyObj.key_ops) !== "[object Array]") {
            fail.push("key.key_ops missing or not Array");
        }

        if (keyObj.key_ops && !testShared.compareUsages(keyObj.key_ops, usages)) {
            fail.push("key.key_ops invalid usage(s)");
        }

        // has kty property equal to 'RSA'
        if (!validation.prop.string(keyObj, "kty", "EC")) {
            fail.push("key.kty !== EC");
        }

        reason.message = fail.join(";  ");

        return (fail.length === 0);
    },
    private: function(keyObj, algorithm, usages, reason) {

        var expLenMax = ecdsaKeyLengths[algorithm.namedCurve];
        var expLenMin = expLenMax;

        this.public(keyObj, algorithm, usages, reason);

        var fail = reason.message ? reason.message.split(";  ") : [];

        // d property is base64url bytes
        if (!validation.prop.isBase64Url(keyObj, "d", expLenMin, expLenMax)) {
            fail.push("key.d is not base64url or has incorrect length");
        }

        reason.message = fail.join(";  ");

        return (fail.length === 0);
    }
};
