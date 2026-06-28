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

aesKWTests();

function aesKWTests() {

    QUnit.module( "AES-KW" );

    var ts = testShared;
    var context = ts.testContext;
    var usages = [["wrapKey", "unwrapKey"], ["wrapKey"], ["unwrapKey"], ["unwrapKey", "wrapKey"]];

    QUnit.test( label + " key import/export raw 128 ", function( assert ) {
        ts.keyImportExportTest( aes.kw._128.raw, usages, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export raw 192 ", function( assert ) {
        ts.keyImportExportTest( aes.kw._192.raw, usages, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export raw 256 ", function( assert ) {
        ts.keyImportExportTest( aes.kw._256.raw, usages, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export jwk 128 ", function( assert ) {
        ts.keyImportExportTest( aes.kw._128.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export jwk 192 ", function( assert ) {
        ts.keyImportExportTest( aes.kw._192.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " key import/export jwk 256 ", function( assert ) {
        ts.keyImportExportTest( aes.kw._256.jwk, undefined, undefined, context( iterations, assert ) );
    } );

    QUnit.test( label + " generateKeyTest 128", function( assert ) {
        ts.keyGenerateTest( aesKWKeyAlg( 128 ), usages, inspectAesKWKey, context( iterations, assert ) );
    } );

    QUnit.test( label + " generateKeyTest 192", function( assert ) {
        ts.keyGenerateTest( aesKWKeyAlg( 192 ), usages, inspectAesKWKey, context( iterations, assert ) );
    } );

    QUnit.test( label + " generateKeyTest 256", function( assert ) {
        ts.keyGenerateTest( aesKWKeyAlg( 256 ), usages, inspectAesKWKey, context( iterations, assert ) );
    } );

    QUnit.test( label + " encrypt/decrypt 128", function( assert ) {
        ts.encryptDecryptTest( aesKWKeyAlg( 128 ), aesKWEncryptAlg, context( iterations, assert ) );
    } );

    QUnit.test( label + " encrypt/decrypt 192", function( assert ) {
        ts.encryptDecryptTest( aesKWKeyAlg( 192 ), aesKWEncryptAlg, context( iterations, assert ) );
    } );

    QUnit.test( label + " encrypt/decrypt 256", function( assert ) {
        ts.encryptDecryptTest( aesKWKeyAlg( 256 ), aesKWEncryptAlg, context( iterations, assert ) );
    } );

    QUnit.test(label + " decrypt native ciphers 128", function(assert) {
        ts.decryptNativeCiphersTest(aes.kw._128.ciphers, context(Math.min(aes.kw._128.ciphers.vectors.length, iterations), assert));
    });

    // QUnit.test(label + " decrypt native ciphers 192", function(assert) {
    //     ts.decryptNativeCiphersTest(aes.kw._192.ciphers, context(Math.min(aes.kw._192.ciphers.vectors.length, iterations), assert));
    // });

    QUnit.test(label + " decrypt native ciphers 256", function(assert) {
        ts.decryptNativeCiphersTest(aes.kw._256.ciphers, context(Math.min(aes.kw._256.ciphers.vectors.length, iterations), assert));
    });

}

// AES-KW specific key property validation
function inspectAesKWKey( keyObj, algorithm, usages, reason /* set reason.message to return fail messages */ ) {

    var fail = [];

    if ( !validation.prop.string( keyObj, "alg", "A" + algorithm.length + "KW" ) ) {
        fail.push( "key.alg !== A" + algorithm.length + "KW" );
    }

    if ( !validation.prop.boolean( keyObj, "ext", true ) ) {
        fail.push( "key.ext !== true" );
    }

    if ( !validation.prop.string( keyObj, "k", /^([A-Za-z0-9-_]+)$/ /* base64url */ ) ) {
        fail.push( "key.k not base64url" );
    }

    // k property converts to bytes array of expected length
    var kBytes = msrCrypto.fromBase64( keyObj.k );
    if ( !testShared.isBytes( kBytes, algorithm.length / 8 ) ) {
        fail.push( "key.k is not bytes" );
    }

    // has key_ops property with expected usages
    if ( Object.prototype.toString.call( keyObj.key_ops ) !== "[object Array]" ) {
        fail.push( "key.key_ops missing or not Array" );
    }

    if ( keyObj.key_ops && !testShared.compareUsages( keyObj.key_ops, usages ) ) {
        fail.push( "key.key_ops invalid usage(s)" );
    }

    if ( !validation.prop.string( keyObj, "kty", "oct" ) ) {
        fail.push( "key.kty !== oct" );
    }

    reason.message = fail.join( ";  " );

    return ( fail.length === 0 );
}

// Generates a new encrypt/decrypt alg
function aesKWEncryptAlg() {
    return {
        name: "AES-KW"
    };
}

function aesKWKeyAlg( length ) {
    return {
        name: "AES-KW",
        length: length
    };
}
