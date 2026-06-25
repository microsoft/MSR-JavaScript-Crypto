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

// NOTE:
//
// Microsoft Edge :
//     does not support 32 or 64 bit tag lengths
//     will fail on jwk keys with 'short' data elements (truncated leading zeros resulting in shorter data array)
//     encrypt/decrypt alg with modulusLength or publicExponent will throw error (only needed on key functions)
//
// Chrome :
//     does not support 192 bit AES keys
//

// tslint:disable: max-line-length

"use strict";

rsaEsTests();

function rsaEsTests() {

    QUnit.module("RSAES-PKCS1-V1_5");

    var ts = testShared;
    var context = ts.testContext;

    QUnit.test(label + " key import/export spki 1024 ", function(assert) {
        ts.keyImportExportTestSpki(
            rsa.es._1024.spki, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export spki 2048 ", function(assert) {
        ts.keyImportExportTestSpki(
            rsa.es._2048.spki, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export spki 4096 ", function(assert) {
        ts.keyImportExportTestSpki(
            rsa.es._4096.spki, undefined, undefined, context(iterations, assert));
    });

    QUnit.test( label + " key import/export jwk 1024 ", function( assert ) {
        ts.keyPairImportExportTest(
            rsa.es._1024.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export jwk 2048 ", function( assert ) {
        ts.keyPairImportExportTest(
            rsa.es._2048.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export jwk 4096 ", function( assert ) {
        ts.keyPairImportExportTest(
            rsa.es._4096.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    //=============================

    QUnit.test( label + " generateKeyTest 1024", function( assert ) {
        ts.keyGeneratePairTest(
            rsaEsKeyAlg( 1024 ), ["encrypt", "decrypt"], inspectRsaEsKey, context( iterations, assert ) );
    } );

    slowTest( label + " generateKeyTest 2048", function( assert ) {
        ts.keyGeneratePairTest(
            rsaEsKeyAlg( 2048 ), ["encrypt", "decrypt"], inspectRsaEsKey, context( iterations, assert ) );
    } );

    slowTest( label + " generateKeyTest 4096", function( assert ) {
        ts.keyGeneratePairTest(
            rsaEsKeyAlg( 4096 ), ["encrypt", "decrypt"], inspectRsaEsKey, context( iterations, assert ) );
    } );

    //=============================

    QUnit.test( label + " encrypt/decrypt 1024", function( assert ) {
        ts.encryptDecryptTest( rsaEsKeyAlg( 1024 ), rsaEsEncryptAlg, context( iterations, assert ) );
    } );

    slowTest( label + " encrypt/decrypt 2048", function( assert ) {
        ts.encryptDecryptTest( rsaEsKeyAlg( 2048 ), rsaEsEncryptAlg, context( iterations, assert ) );
    } );

    slowTest( label + " encrypt/decrypt 4096", function( assert ) {
        ts.encryptDecryptTest( rsaEsKeyAlg( 4096 ), rsaEsEncryptAlg, context( iterations, assert ) );
    } );

    //=============================

    QUnit.test(label + " decrypt native ciphers 1024", function(assert) {
        ts.decryptNativeCiphersTest(rsa.es._1024.ciphers, context(iterations, assert));
    });

    QUnit.test( label + " decrypt native ciphers 2048", function( assert ) {
        ts.decryptNativeCiphersTest( rsa.es._2048.ciphers, context( iterations, assert ) );
    } );

    slowTest( label + " decrypt native ciphers 4096", function( assert ) {
        ts.decryptNativeCiphersTest( rsa.es._4096.ciphers, context( iterations, assert ) );
    } );

}

function rsaEsKeyAlg(modulusLength) {
    return {
        name: "RSAES-PKCS1-V1_5",
        modulusLength: modulusLength,
        publicExponent: testShared.arr([0x01, 0x00, 0x01])
    };
}

function rsaEsEncryptAlg() {
    var alg = {
        name: "RSAES-PKCS1-V1_5"
    };

    return alg;
}

var inspectRsaEsKey = {
    public: function(keyObj, algorithm, usages, reason) {
        //     "publicKey": {
        //         "alg": "RSA1_5",
        //         "e": "AQAB",
        //         "ext": true,
        //         "key_ops": [
        //             "encrypt",
        //         ],
        //         "kty": "RSA",
        //         "n": "ush3d1BXcw3VjzD8jhff8GZD4KE5gmeJ...",
        //     },

        var fail = [];
        var expLenMax = algorithm.modulusLength / 8;
        var expLenMin = expLenMax - 2;

        // has alg property RSA1_5)
        if (!validation.prop.string(keyObj, "alg", "RSA1_5")) {
            fail.push("key.alg !== " + "RSA1_5");
        }

        // has ext property equal to true
        if (!validation.prop.boolean(keyObj, "ext", true)) {
            fail.push("key.ext !== true");
        }

        // has e property that is base64url
        if (!validation.prop.isBase64Url(keyObj, "e")) {
            fail.push("key.e !== true");
        }

        // has n property that is base64url
        if (!validation.prop.isBase64Url(keyObj, "n", expLenMin, expLenMax)) {
            fail.push("key.n !== true");
        }

        // has key_ops property with expected usages
        if (Object.prototype.toString.call(keyObj.key_ops) !== "[object Array]") {
            fail.push("key.key_ops missing or not Array");
        }

        if (keyObj.key_ops && !testShared.compareUsages(keyObj.key_ops, usages)) {
            fail.push("key.key_ops invalid usage(s)");
        }

        // has kty property equal to 'RSA'
        if (!validation.prop.string(keyObj, "kty", "RSA")) {
            fail.push("key.kty !== RSA");
        }

        reason.message = fail.join(";  ");

        return (fail.length === 0);
    },
    private: function(keyObj, algorithm, usages, reason) {
        //   "privateKey": {
        //       "alg": "RSAES-PKCS1-V1_5",
        //       "d": "Aw88kbpBrHNKD73kLSmr8-Kg8wGBESdEA2SwRk6JLYhQjUmqwed7nW2WfR69ZY5dulPhl1BpGy...",
        //       "dp": "MzaNxLv5qiZ5tcXSZiQUuCr9Z1ivnNGd9HGK3xKLN4tqJGkqjEuBwThQFVaa-SkTU5bIK4o0AuX0sSRI8X26Yw",
        //       "dq": "hC-5kaiWpoBqWfndCNBFo7h4SVLe-g7dHSo-XN2uVCTykt-3kan_hfuzkcUNSb4WBsCvjzeSX5TySPPrDILKQQ",
        //       "e": "AQAB",
        //       "ext": true,
        //       "key_ops": [
        //           "decrypt",
        //       ],
        //       "kty": "RSA",
        //       "n": "ush3d1BXcw3VjzD8jhff8GZD4KE5gmeJZeA0OW03dgrAWjHZ-wykw1tvLXvFaAlePiXl0IteNXc92...",
        //       "p": "6l2mtx2Xdtvn-rNMPWTsrj-hXwwno8hZM5k8xV_ouiuciSGR8lgFhM0GBJapx9XADVZamb0sDEMiZRZmY4tygw",
        //       "q": "zAZglPR34FqV9QpbpVSuT-wB9tfCALLK-X2jA7IyNX9eRn5ZAmQT2PmpJ3ncGH-S1K9716X1oxBeO888qTXvQQ",
        //       "qi": "1lFKci4J7DlMzmi0J5_MdfNawjme8uJLBU4orqt_8ygqDQy9K5I3Qy5Lo6ifS9o9_yBVZmGZ-HInkTvppv82-w",
        //   },

        var expLenMin;
        var expLenMax;

        this.public(keyObj, algorithm, ["decrypt"], reason);

        var fail = reason.message ? reason.message.split(";  ") : [];

        expLenMax = algorithm.modulusLength / 8;
        expLenMin = expLenMax - 2;

        // d property is base64url bytes
        if (!validation.prop.isBase64Url(keyObj, "d", expLenMin, expLenMax)) {
            fail.push("key.d !== true");
        }

        expLenMax = algorithm.modulusLength / 16;
        expLenMin = expLenMax - 2;

        // dp property is base64url bytes
        if (!validation.prop.isBase64Url(keyObj, "dp", expLenMin, expLenMax)) {
            fail.push("key.dp !== true");
        }

        // dq property is base64url bytes
        if (!validation.prop.isBase64Url(keyObj, "dq", expLenMin, expLenMax)) {
            fail.push("key.dq !== true");
        }

        // p property is base64url bytes
        if (!validation.prop.isBase64Url(keyObj, "p", expLenMin, expLenMax)) {
            fail.push("key.p !== true");
        }

        // q property is base64url bytes
        if (!validation.prop.isBase64Url(keyObj, "q", expLenMin, expLenMax)) {
            fail.push("key.q !== true");
        }

        // qi property is base64url bytes
        if (!validation.prop.isBase64Url(keyObj, "qi", expLenMin, expLenMax)) {
            fail.push("key.qi fail");
        }

        reason.message = fail.join(";  ");

        return (fail.length === 0);
    }
};
