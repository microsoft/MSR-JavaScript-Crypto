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

var msrcryptoHmac = function( keyBytes, hashFunction ) {

    var blockSize = { "384": 128, "512": 128 }[hashFunction.name.replace( /SHA-/, "" )] || 64;
    var ipad;
    var opad;
    var paddedKey = padKey();
    var keyXorOpad;
    var keyXorIpad;
    var k0IpadText;

    function xorArrays( array1, array2 ) {
        var newArray = new Array( array1 );
        for ( var j = 0; j < array1.length; j++ ) {
            // tslint:disable-next-line: no-bitwise
            newArray[j] = array1[j] ^ array2[j];
        }
        return newArray;
    }

    // Returns a new Array with zeros padded on the end
    function padZeros( bytes, paddedLength ) {
        var paddedArray = bytes.slice();
        for ( var j = bytes.length; j < paddedLength; j++ ) {
            paddedArray.push( 0 );
        }
        return paddedArray;
    }

    function padKey() {

        if ( keyBytes.length === blockSize ) {
            return keyBytes;
        }

        if ( keyBytes.length > blockSize ) {
            return padZeros( hashFunction.computeHash( keyBytes ), blockSize );
        }

        // If keyBytes.length < blockSize
        return padZeros( keyBytes, blockSize );

    }

    function processHmac( messageBytes ) {

        // If this is the first process call, do some initial computations
        if ( !k0IpadText ) {
            k0IpadText = keyXorIpad.concat( messageBytes );
            hashFunction.process( k0IpadText );
        } else {
            hashFunction.process( messageBytes );
        }
        return;
    }

    function finishHmac() {

        var hashK0IpadText = hashFunction.finish();

        var k0IpadK0OpadText = keyXorOpad.concat( hashK0IpadText );

        return hashFunction.computeHash( k0IpadK0OpadText );
    }

    function clearState() {
        keyBytes = null;
        hashFunction = null;
        paddedKey = null;
    }

    /// First time initialization
    ipad = new Array( blockSize );
    opad = new Array( blockSize );
    for ( var i = 0; i < blockSize; i++ ) { ipad[i] = 0x36; opad[i] = 0x5c; }
    keyXorIpad = xorArrays( paddedKey, ipad );
    keyXorOpad = xorArrays( paddedKey, opad );
    return {

        computeHmac: function( dataBytes, key, hashAlgorithm ) {
            /// <summary>Computes the HMAC</summary>
            /// <param name="dataBytes" type="Array">Data to MAC</param>
            /// <param name="key" type="Array">Array of bytes for key</param>
            /// <param name="hashAlgorithm" type="String">sha-224, sha-256, sha-384, sha-512 (default sha-256)</param>
            /// <returns type="Array">Returns an array of bytes as the HMAC</returns>

            processHmac( dataBytes );
            var result = finishHmac();
            clearState();
            return result;
        },

        process: function( dataBytes, key, hashAlgorithm ) {
            /// <summary>Computes a partial HMAC to be followed by subsequent process calls or finish()</summary>
            /// <param name="dataBytes" type="Array">Data to MAC</param>
            /// <param name="key" type="Array">Array of bytes for key</param>
            /// <param name="hashAlgorithm" type="String">sha-224, sha-256, sha-384, sha-512 (default sha-256)</param>

            processHmac( dataBytes );
            return null;
        },

        finish: function( key, hashAlgorithm ) {
            /// <summary>Computes the final HMAC upon partial computations from previous process() calls.</summary>
            /// <param name="key" type="Array">Array of bytes for key</param>
            /// <param name="hashAlgorithm" type="String">sha-224, sha-256, sha-384, sha-512 (default sha-256)</param>
            /// <returns type="Array">Returns an array of bytes as the HMAC</returns>

            var result = finishHmac();
            clearState();
            return result;
        }

    };
};

if ( typeof operations !== "undefined" ) {

    var hmacInstances = {};

    msrcryptoHmac.signHmac = function( p ) {

        var hashName = p.keyHandle.algorithm.hash.name.toUpperCase(),
            hashAlg = msrcryptoHashFunctions[hashName](),
            result,
            id = p.workerid;

        if ( !hmacInstances[id] ) {
            hmacInstances[id] = msrcryptoHmac( p.keyData, hashAlg );
        }

        if ( p.operationSubType === "process" ) {
            hmacInstances[id].process( p.buffer );
            return null;
        }

        if ( p.operationSubType === "finish" ) {
            result = hmacInstances[id].finish();
            hmacInstances[id] = null;
            return result;
        }

        result = hmacInstances[id].computeHmac( p.buffer );
        hmacInstances[id] = null;
        return result;
    };

    msrcryptoHmac.verifyHmac = function( p ) {

        var hashName = p.keyHandle.algorithm.hash.name.toUpperCase(),
            hashAlg = msrcryptoHashFunctions[hashName](),
            result,
            id = p.workerid;

        if ( !hmacInstances[id] ) {
            hmacInstances[id] = msrcryptoHmac( p.keyData, hashAlg );
        }

        if ( p.operationSubType === "process" ) {
            hmacInstances[id].process( p.buffer );
            return null;
        }

        if ( p.operationSubType === "finish" ) {
            result = hmacInstances[id].finish();
            result = msrcryptoUtilities.arraysEqual( result, p.signature );
            hmacInstances[id] = null;
            return result;
        }

        result = hmacInstances[id].computeHmac( p.buffer );
        result = msrcryptoUtilities.arraysEqual( result, p.signature );
        hmacInstances[id] = null;
        return result;
    };

    msrcryptoHmac.generateKey = function( p ) {

        // keyLength = hash alg block size with length is not specified
        var defaultKeyLengths = { "SHA-1": 64, "SHA-224": 64, "SHA-256": 64, "SHA-384": 128, "SHA-512": 128 };

        var keyLength = p.algorithm.length;

        if ( !keyLength ) {
            keyLength = defaultKeyLengths[p.algorithm.hash.name.toUpperCase()];
        }

        return {
            type: "keyGeneration",
            keyData: msrcryptoPseudoRandom.getBytes( keyLength ),
            keyHandle: new MsrCryptoKey({
                algorithm: p.algorithm,
                extractable: p.extractable,
                usages: null || p.usages,
                type: "secret"
            })
        };
    };

    msrcryptoHmac.importKey = function( p ) {
        var keyObject,
            keyBits = p.keyData.length * 8;

        if ( p.format === "jwk" ) {
            keyObject = msrcryptoJwk.jwkToKey( p.keyData, p.algorithm, ["k"] );
            keyObject.alg = keyObject.alg.replace( "HS", "SHA-" );
        } else if ( p.format === "raw" ) {
            keyObject = { k: msrcryptoUtilities.toArray( p.keyData ) };
        } else {
            throw new Error( "unsupported import format" );
        }

        return {
            type: "keyImport",
            keyData: keyObject.k,
            keyHandle: new MsrCryptoKey({
                algorithm: { name: "HMAC", hash: { name: p.algorithm.hash.name } },
                extractable: p.extractable || keyObject.extractable,
                usages: p.usages,
                type: "secret"
            })
        };

    };

    msrcryptoHmac.exportKey = function( p ) {

        if ( p.format === "jwk" ) {
            return { type: "keyExport", keyHandle: msrcryptoJwk.keyToJwk( p.keyHandle, p.keyData ) };
        }

        if ( p.format === "raw" ) {
            return { type: "keyExport", keyHandle: p.keyData };
        }

        throw new Error( "unsupported export format" );
    };

    operations.register( "importKey", "HMAC", msrcryptoHmac.importKey );
    operations.register( "exportKey", "HMAC", msrcryptoHmac.exportKey );
    operations.register( "generateKey", "HMAC", msrcryptoHmac.generateKey );
    operations.register( "sign", "HMAC", msrcryptoHmac.signHmac );
    operations.register( "verify", "HMAC", msrcryptoHmac.verifyHmac );
}
