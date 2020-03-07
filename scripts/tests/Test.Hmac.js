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

hmacTests();

function hmacTests() {

    QUnit.module( "HMAC" );

    var ts = testShared;
    var context = ts.testContext;
    var hmacUsages = [[VERIFY, SIGN], [SIGN], [VERIFY], [SIGN, VERIFY]];

    QUnit.test( label + " generateKeyTest SHA-1", function( assert ) {
        ts.keyGenerateTest( hmacKeyAlg( "SHA-1" ), hmacUsages, inspectHmacKey, context( iterations, assert ) );
    } );

    QUnit.test( label + " generateKeyTest SHA-256", function( assert ) {
        ts.keyGenerateTest( hmacKeyAlg( "SHA-256" ), hmacUsages, inspectHmacKey, context( iterations, assert ) );
    } );

    QUnit.test( label + " generateKeyTest SHA-384", function( assert ) {
        ts.keyGenerateTest( hmacKeyAlg( "SHA-384" ), hmacUsages, inspectHmacKey, context( iterations, assert ) );
    } );

    QUnit.test( label + " generateKeyTest SHA-512", function( assert ) {
        ts.keyGenerateTest( hmacKeyAlg( "SHA-512" ), hmacUsages, inspectHmacKey, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature SHA-1 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            hmacKeyAlg( "SHA-1" ), hmac.sign_verify.sha1, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature SHA-256 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            hmacKeyAlg( "SHA-256" ), hmac.sign_verify.sha256, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature SHA-384 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            hmacKeyAlg( "SHA-384" ), hmac.sign_verify.sha384, context( iterations, assert ) );
    } );

    QUnit.test( label + " verify native signature SHA-512 ", function( assert ) {
        ts.verifyNativeSignatureTest(
            hmacKeyAlg( "SHA-512" ), hmac.sign_verify.sha512, context( iterations, assert ) );
    } );

    // ===========================================================================================================

    QUnit.test( label + " sign/verify SHA-1", function( assert ) {
        ts.signVerifyTest( hmacKeyAlg( "SHA-1" ), {name: "HMAC"}, context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify SHA-256", function( assert ) {
        ts.signVerifyTest( hmacKeyAlg( "SHA-256" ), { name: "HMAC" }, context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify SHA-384", function( assert ) {
        ts.signVerifyTest( hmacKeyAlg( "SHA-384" ), { name: "HMAC" }, context( iterations, assert ) );
    } );

    QUnit.test( label + " sign/verify SHA-512", function( assert ) {
        ts.signVerifyTest( hmacKeyAlg( "SHA-512" ), { name: "HMAC" }, context( iterations, assert ) );
    } );

    // ===========================================================================================================

    QUnit.test( label + " key import/export jwk SHA-1 ", function( assert ) {
        ts.keyImportExportTest(
            hmac.sha1.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export jwk SHA-256 ", function( assert ) {
        ts.keyImportExportTest(
            hmac.sha256.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export jwk SHA-384 ", function( assert ) {
        ts.keyImportExportTest(
            hmac.sha384.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export jwk SHA-512 ", function( assert ) {
        ts.keyImportExportTest(
            hmac.sha512.jwk, undefined, undefined, context( iterations, assert ) );
    } );
}

// function hmacKeyValidateJwk( actualKey, expectedKey ) {

//     // key_ops usages may not be in the same order and will fail the deepEquals check
//     // we'll verify they have the same items. Then set them to be the same before deepEquals
//     if ( compareUsages( actualKey.key_ops, expectedKey.key_ops ) === false ) {
//         QUnit.assert.ok( false, "usages do not match." );
//         return false;
//     }
//     expectedKey.key_ops = actualKey.key_ops.slice();

//     QUnit.assert.deepEqual( actualKey, expectedKey, JSON.stringify( expectedKey ) );
// }

// function hmacKeyValidateRaw( actualKey, expectedKey ) {
//     QUnit.assert.deepEqual( toArray( actualKey ), toArray( expectedKey ), JSON.stringify( expectedKey ) );
// }

function hmacKeyAlg( hashAlg ) {
    return {
        name: "HMAC",
        hash: { name: hashAlg }
    };
}

var inspectHmacKey = function( keyObj, algorithm, usages, reason /* set reason.message to return fail messages */ ) {

    // {
    //     kty: "oct",
    //     k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
    //     alg: "HS256",
    //     ext: true,
    // }

    var fail = [];

    var algNames = { "SHA-1": "HS1", "SHA-256": "HS256", "SHA-384": "HS384", "SHA-512": "HS512" };
    var keyLengths = { "SHA-1": 64, "SHA-224": 64, "SHA-256": 64, "SHA-384": 128, "SHA-512": 128 };

    var expLenMax = keyLengths[algorithm.hash.name];
    var expLenMin = expLenMax - 0;

    // has kty property equal to 'oct'
    if ( !validation.prop.string( keyObj, "alg", algNames[algorithm.hash.name] ) ) {
        fail.push( "key.kty !== " + algNames[algorithm.hash.name] );
    }

    // has ext property equal to true
    if ( !validation.prop.boolean( keyObj, "ext", true ) ) {
        fail.push( "key.ext !== true" );
    }

    // has e property that is base64url
    if ( !validation.prop.isBase64Url( keyObj, "k", expLenMin, expLenMax ) ) {
        fail.push( "key.k is not base64url or has incorrect length" );
    }

    // has key_ops property with expected usages
    if ( Object.prototype.toString.call( keyObj.key_ops ) !== "[object Array]" ) {
        fail.push( "key.key_ops missing or not Array" );
    }

    if ( keyObj.key_ops && !testShared.compareUsages( keyObj.key_ops, usages ) ) {
        fail.push( "key.key_ops invalid usage(s)" );
    }

    // has kty property equal to 'oct'
    if ( !validation.prop.string( keyObj, "kty", "oct" ) ) {
        fail.push( "key.kty !== oct" );
    }

    reason.message = fail.join( ";  " );

    return ( fail.length === 0 );

};
