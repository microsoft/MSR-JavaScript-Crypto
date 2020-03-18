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

pbkdf2Tests();

function pbkdf2Tests() {

    QUnit.module("PBKDF2");

    var ts = testShared;
    var context = ts.testContext;

    QUnit.test(label + " ts.deriveBitsTest Password --> bits ", function(assert) {
        var vectorSet = pbkdf2.DeriveBits;
        ts.deriveBitsTest(vectorSet, context(vectorSet.vectors.length, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest Password --> Aes-Gcm-128 ", function(assert) {
        var vectorSet = pbkdf2.aes.gcm._128.DeriveKey;
        ts.deriveKeyTest(vectorSet, undefined, context(vectorSet.vectors.length, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest Password --> Aes-Gcm-256 ", function(assert) {
        var vectorSet = pbkdf2.aes.gcm._256.DeriveKey;
        ts.deriveKeyTest(vectorSet, undefined, context(vectorSet.vectors.length, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest Password --> Aes-Cbc-128 ", function(assert) {
        var vectorSet = pbkdf2.aes.cbc._128.DeriveKey;
        ts.deriveKeyTest(vectorSet, undefined, context(vectorSet.vectors.length, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest Password --> Aes-Cbc-256 ", function(assert) {
        var vectorSet = pbkdf2.aes.cbc._256.DeriveKey;
        ts.deriveKeyTest(vectorSet, undefined, context(vectorSet.vectors.length, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest Password --> Hmac-Sha1 ", function(assert) {
        var vectorSet = pbkdf2.hmac.sha1.DeriveKey;
        ts.deriveKeyTest(vectorSet, undefined, context(vectorSet.vectors.length, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest Password --> Hmac-Sha256 ", function(assert) {
        var vectorSet = pbkdf2.hmac.sha256.DeriveKey;
        ts.deriveKeyTest(vectorSet, undefined, context(vectorSet.vectors.length, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest Password --> Hmac-Sha384 ", function(assert) {
        var vectorSet = pbkdf2.hmac.sha384.DeriveKey;
        ts.deriveKeyTest(vectorSet, undefined, context(vectorSet.vectors.length, assert));
    });

    QUnit.test(label + " ts.deriveKeyTest Password --> Hmac-Sha512 ", function(assert) {
        var vectorSet = pbkdf2.hmac.sha512.DeriveKey;
        ts.deriveKeyTest(vectorSet, undefined, context(vectorSet.vectors.length, assert));
    });

}
