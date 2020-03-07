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

hashTests();

function hashTests() {

    QUnit.module( "SHA2" );

    var ts = testShared;
    var context = ts.testContext;

    QUnit.test( label + "  vectors SHA-1", function( assert ) {
        ts.hashTest( sha2.sha1, context( sha2.sha1.vectors.length, assert ) );
    } );

    QUnit.test( label + "  vectors SHA-224", function( assert ) {
        ts.hashTest( sha2.sha224, context( sha2.sha224.vectors.length, assert ) );
    } );

    QUnit.test( label + "  vectors SHA-256", function( assert ) {
        ts.hashTest( sha2.sha256, context( sha2.sha256.vectors.length, assert ) );
    } );

    QUnit.test( label + "  vectors SHA-384", function( assert ) {
        ts.hashTest( sha2.sha384, context( sha2.sha384.vectors.length, assert ) );
    } );

    QUnit.test( label + "  vectors SHA-512", function( assert ) {
        ts.hashTest( sha2.sha512, context( sha2.sha512.vectors.length, assert ) );
    } );
}
