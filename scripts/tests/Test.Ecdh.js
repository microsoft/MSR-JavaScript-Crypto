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

ecdhTests();

function ecdhTests() {

    QUnit.module("ECDH");

    var ts = testShared;
    var context = ts.testContext;

    var ecdhUsages = {
        public: [[]],
        private: [["deriveKey"], ["deriveBits"], ["deriveKey", "deriveBits"]]
    };

    QUnit.test(label + " key import/export raw P-256 ", function(assert) {
        // ECDH raw export only exports public key
        ts.keyImportExportTest(ecdh.p256.raw, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw P-384 ", function(assert) {
        // ECDH raw export only exports public key
        ts.keyImportExportTest(ecdh.p384.raw, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw P-521 ", function(assert) {
        // ECDH raw export only exports public key
        ts.keyImportExportTest(ecdh.p521.raw, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export spki P-256 ", function(assert) {
        ts.keyImportExportTestSpki(ecdh.p256.spki, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export spki P-384 ", function(assert) {
        ts.keyImportExportTestSpki(ecdh.p384.spki, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export spki P-521 ", function(assert) {
        ts.keyImportExportTestSpki(ecdh.p521.spki, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export pkcs8 P-256 ", function(assert) {
        ts.keyImportExportTestSpki(ecdh.p256.pkcs8, ecdhUsages.private, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export pkcs8 P-384 ", function(assert) {
        ts.keyImportExportTestSpki(ecdh.p384.pkcs8, ecdhUsages.private, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export pkcs8 P-521 ", function(assert) {
        ts.keyImportExportTestSpki(ecdh.p521.pkcs8, ecdhUsages.private, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk P-256 ", function(assert) {
        ts.keyPairImportExportTest(ecdh.p256.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk P-384 ", function(assert) {
        ts.keyPairImportExportTest(ecdh.p384.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk P-521 ", function(assert) {
        ts.keyPairImportExportTest(ecdh.p521.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest  P-256", function(assert) {
        ts.keyGeneratePairTest(ecdhKeyAlg("P-256"), ["deriveKey", "deriveBits"], inspectEcdhKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest  P-384", function(assert) {
        ts.keyGeneratePairTest(ecdhKeyAlg("P-384"), ["deriveKey", "deriveBits"], inspectEcdhKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest  P-521", function(assert) {
        ts.keyGeneratePairTest(ecdhKeyAlg("P-521"), ["deriveKey", "deriveBits"], inspectEcdhKey, context(iterations, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest P-256 --> Aes-Cbc-256 ", function(assert) {
        ts.deriveKeyTest(ecdh.p256.DeriveKey, undefined, context(iterations, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest P-384 --> Aes-Cbc-128 ", function(assert) {
        ts.deriveKeyTest(ecdh.p384.DeriveKey, undefined, context(iterations, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest P-521 --> Aes-Gcm-256 ", function(assert) {
        ts.deriveKeyTest(ecdh.p521.DeriveKey, undefined, context(iterations, assert));
    });

    QUnit.test(label + " ts.deriveBitsTest P-256 --> 256-bits ", function(assert) {
        ts.deriveBitsTest(ecdh.p256.DeriveBits, context(iterations, assert));
    });

    QUnit.test(label + " ts.deriveBitsTest P-384 --> 384-bits ", function(assert) {
        ts.deriveBitsTest(ecdh.p384.DeriveBits, context(iterations, assert));
    });

    QUnit.test(label + " ts.deriveBitsTest P-521 --> 528-bits ", function(assert) {
        ts.deriveBitsTest(ecdh.p521.DeriveBits, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP256D1", function(assert) {
        ts.keyGeneratePairTest(ecdhKeyAlg("NUMSP256D1"), ["deriveKey", "deriveBits"], inspectEcdhKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP384D1", function(assert) {
        ts.keyGeneratePairTest(ecdhKeyAlg("NUMSP384D1"), ["deriveKey", "deriveBits"], inspectEcdhKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP512D1", function(assert) {
        ts.keyGeneratePairTest(ecdhKeyAlg("NUMSP512D1"), ["deriveKey", "deriveBits"], inspectEcdhKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP256T1", function(assert) {
        ts.keyGeneratePairTest(ecdhKeyAlg("NUMSP256T1"), ["deriveKey", "deriveBits"], inspectEcdhKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP384T1", function(assert) {
        ts.keyGeneratePairTest(ecdhKeyAlg("NUMSP384T1"), ["deriveKey", "deriveBits"], inspectEcdhKey, context(iterations, assert));
    });

    QUnit.test(label + " generateKeyTest NUMSP512T1", function(assert) {
        ts.keyGeneratePairTest(ecdhKeyAlg("NUMSP512T1"), ["deriveKey", "deriveBits"], inspectEcdhKey, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP256D1 ", function(assert) {
        ts.keyPairImportExportTest(ecdh.numsp256d1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP384D1 ", function(assert) {
        ts.keyPairImportExportTest(ecdh.numsp384d1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP512D1 ", function(assert) {
        ts.keyPairImportExportTest(ecdh.numsp512d1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP256T1 ", function(assert) {
        ts.keyPairImportExportTest(ecdh.numsp256t1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP384T1 ", function(assert) {
        ts.keyPairImportExportTest(ecdh.numsp384t1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export jwk NUMSP512T1 ", function(assert) {
        ts.keyPairImportExportTest(ecdh.numsp512t1.jwk, undefined, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP256D1 ", function(assert) {
        ts.keyImportExportTest(ecdh.numsp256d1.raw, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP384D1 ", function(assert) {
        ts.keyImportExportTest(ecdh.numsp384d1.raw, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP512D1 ", function(assert) {
        ts.keyImportExportTest(ecdh.numsp512d1.raw, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP256T1 ", function(assert) {
        ts.keyImportExportTest(ecdh.numsp256t1.raw, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP384T1 ", function(assert) {
        ts.keyImportExportTest(ecdh.numsp384t1.raw, ecdhUsages.public, undefined, context(iterations, assert));
    });

    QUnit.test(label + " key import/export raw NUMSP512T1 ", function(assert) {
        ts.keyImportExportTest(ecdh.numsp512t1.raw, ecdhUsages.public, undefined, context(iterations, assert));
    });
}

var ecdhKeyLengths = {
    "P-256": 32,
    "P-384": 48,
    "P-521": 66,
    "NUMSP256D1": 32,
    "NUMSP256T1": 32,
    "NUMSP384D1": 48,
    "NUMSP384T1": 48,
    "NUMSP512D1": 64,
    "NUMSP512T1": 64
};

function ecdhKeyAlg(namedCurve) {
    return {
        name: "ECDH",
        namedCurve: namedCurve
    };
}

var inspectEcdhKey = {
    public: function(keyObj, algorithm, usages, reason) {

        var fail = [];
        var expLenMax = ecdhKeyLengths[algorithm.namedCurve];
        var expLenMin = expLenMax - 2;

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
        // {
        //     "publicKey":
        //     {
        //         "crv": "P-521",
        //         "ext": true,
        //         "key_ops": [],
        //         "kty": "EC",
        //         "x": "AcThC2XVslnUodlFE7a1GduKl_Y4ZwqKEImbmCQR-qeE72TOks3vymiVTjHF84S4ASboyCdGuXrBtuYVUO9DZwTo",
        //         "y": "AZCxpia5Bs9rGZ_BVLuFLb5vZbIg2zQnsCkPrNuZC_yyn95o1C9QhdHtgG6AN0doU5szQ_Rpb72LPOj1phStohBn"
        //     },
        //     "privateKey": {
        //         // all of public key + d
        //         "key_ops": ["deriveBits", "deriveKey"],
        //         "d": "ACdJfF-OVXloqPVvwMAc770Grkogs6FctANcyQ9elPJesD1hUxJ_ihR_1q-7t4P218dVL2PfbA6LCBiQcNG6jR6w",
        //     }
        // }

        var expLenMax = ecdhKeyLengths[algorithm.namedCurve];
        var expLenMin = expLenMax - 2;

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
