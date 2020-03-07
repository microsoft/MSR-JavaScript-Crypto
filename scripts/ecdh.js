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

var msrcryptoEcdh = function( curve ) {

    var btd = cryptoMath.bytesToDigits,
        dtb = cryptoMath.digitsToBytes,
        e = curve,
        ecop = new cryptoECC.EllipticCurveOperatorFp( curve );

    function generateKey( privateKeyBytes ) {
        /// <summary></summary>
        /// <param name="privateKeyBytes" type="Array" optional="true">
        ///     For testing purposes we allow the key bytes to be passed in
        ///     instead of randomly generated.
        /// </param>
        /// <returns type=""></returns>

        var privateKey = [],
            randomBytes = msrcryptoPseudoRandom.getBytes(
                curve.order.length * cryptoMath.DIGIT_NUM_BYTES );

        // allows test code to generate specific private keys
        /* debug-block */
        randomBytes = privateKeyBytes || randomBytes;
        /* end-debug-block */

        cryptoMath.reduce(
            cryptoMath.bytesToDigits( randomBytes ),
            e.order,
            privateKey );

        var publicKey = e.allocatePointStorage( );

        ecop.scalarMultiply( privateKey, e.generator, publicKey );

        return {
            privateKey: {
                x: dtb( publicKey.x ),
                y: dtb( publicKey.y ),
                d: dtb( privateKey )
            },
            publicKey: {
                x: dtb( publicKey.x ),
                y: dtb( publicKey.y )
            }
        };
    }

    function deriveBits( privateKey, publicKey, length ) {

        var publicPoint = new cryptoECC.EllipticCurvePointFp(
            e, false, btd( publicKey.x ), btd( publicKey.y ), null, false );

        var sharedSecretPoint = e.allocatePointStorage();
        ecop.convertToJacobianForm( sharedSecretPoint );
        ecop.convertToMontgomeryForm( sharedSecretPoint );

        ecop.scalarMultiply( btd( privateKey.d ), publicPoint, sharedSecretPoint );

        ecop.convertToAffineForm( sharedSecretPoint );
        ecop.convertToStandardForm( sharedSecretPoint );

        var secretBytes = cryptoMath.digitsToBytes( sharedSecretPoint.x, true, publicKey.x.length );

        if ( length && secretBytes.length * 8 < length ) {
            throw new Error( "DataError" );
        }

        // handle when bit lenght is not incrment of 8
        secretBytes = length ? secretBytes.slice( 0, Math.ceil( length / 8 ) ) : secretBytes;

        var bits = length % 8;
        // tslint:disable-next-line: no-bitwise
        var mask = bits === 0 ? 0xFF : 0xFF00 >>> bits;
        // tslint:disable-next-line: no-bitwise
        secretBytes[secretBytes.length - 1] = secretBytes[secretBytes.length - 1] & mask;

        return secretBytes;
    }

    function computePublicKey( privateKeyBytes ) {

        if ( !e.generator.isInMontgomeryForm ) {
            ecop.convertToMontgomeryForm( e.generator );
        }

        var publicKey = e.allocatePointStorage();
        ecop.convertToJacobianForm( publicKey );
        ecop.convertToMontgomeryForm( publicKey );
        ecop.scalarMultiply( btd( privateKeyBytes ), e.generator, publicKey );

        return {
            x: dtb( publicKey.x ),
            y: dtb( publicKey.y )
        };
    }

    return {

        generateKey: generateKey,
        deriveBits: deriveBits,
        computePublicKey: computePublicKey
    };

};

var ecdhInstance = null;

if ( typeof operations !== "undefined" ) {

    msrcryptoEcdh.deriveBits = function( p ) {

        var curve = cryptoECC.createCurve( p.algorithm.namedCurve.toUpperCase() );

        var privateKey = p.keyData;

        var publicKey = p.additionalKeyData;

        ecdhInstance = msrcryptoEcdh( curve );

        var secretBytes = ecdhInstance.deriveBits( privateKey, publicKey, p.length );

        return secretBytes;
    };

    msrcryptoEcdh.deriveKey = function( p ) {

        throw new Error( "not supported" );

        return secretBytes;
    };

    msrcryptoEcdh.generateKey = function( p ) {

        var curve = cryptoECC.createCurve( p.algorithm.namedCurve.toUpperCase() );

        ecdhInstance = msrcryptoEcdh( curve );

        var keyPairData = ecdhInstance.generateKey();

        return {
            type: "keyPairGeneration",
            keyPair: {
                publicKey: {
                    keyData: keyPairData.publicKey,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: [],
                        type: "public"
                    }
                },
                privateKey: {
                    keyData: keyPairData.privateKey,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: p.usages,
                        type: "private"
                    }
                }
            }
        };
    };

    msrcryptoEcdh.importKey = function( p ) {

        if ( p.format === "raw" ) {

            // raw key will be public only it the form:
            // 4 | <x data bytes> | <y data bytes>

            var keyData = p.keyData;

            if ( keyData[0] !== 4 ) { throw new Error( "DataError" ); }

            // tslint:disable-next-line: no-bitwise
            var elementSize = ~~( (keyData.length - 1 ) / 2 );

            var curveName = p.algorithm.namedCurve.toUpperCase( );

            var x = keyData.slice( 1, elementSize + 1 ),
                y = keyData.slice( elementSize + 1 );

            if ( cryptoECC.validatePoint( curveName, x, y ) === false )  {
                throw new Error( "DataError" );
            }

            return {
                type: "keyImport",
                keyData: { x: x, y: y },
                keyHandle: {
                    algorithm: p.algorithm,
                    extractable: p.extractable || keyObject.extractable,
                    usages: p.usages,
                    type: "public"
                }
            };
        }

        if ( p.format === "jwk" ) {

            var keyObject = msrcryptoJwk.jwkToKey( p.keyData, p.algorithm, ["x", "y", "d", "crv"] );

            // If only private key data 'd' is imported, create x and y
            if ( keyObject.d && ( !keyObject.x || !keyObject.y ) ) {

                var curve = cryptoECC.createCurve( p.algorithm.namedCurve.toUpperCase() );

                ecdhInstance = msrcryptoEcdh( curve );

                var publicKey = ecdhInstance.computePublicKey( keyObject.d );

                keyObject.x = publicKey.x;
                keyObject.y = publicKey.y;
            }

            if ( cryptoECC.validatePoint( p.algorithm.namedCurve.toUpperCase( ), keyObject.x, keyObject.y ) === false ) {
                throw new Error( "DataError" );
            }

            return {
                type: "keyImport",
                keyData: keyObject,
                keyHandle: {
                    algorithm: p.algorithm,
                    extractable: p.extractable || keyObject.extractable,
                    usages: p.usages,
                    type: keyObject.d ? "private" : "public"
                }
            };
        }
    };

    msrcryptoEcdh.exportKey = function( p ) {

        if ( p.format === "raw" && p.keyHandle.type === "public" ) {

            var keyData = [4].concat( p.keyData.x, p.keyData.y );

            return { type: "keyExport", keyHandle: keyData };
        }

        if ( p.format === "jwk" ) {
            var jsonKeyStringArray = msrcryptoJwk.keyToJwk( p.keyHandle, p.keyData );
            return { type: "keyExport", keyHandle: jsonKeyStringArray };
        }

        throw new Error( "unsupported export format." );
    };

    operations.register( "importKey", "ecdh", msrcryptoEcdh.importKey );
    operations.register( "exportKey", "ecdh", msrcryptoEcdh.exportKey );
    operations.register( "generateKey", "ecdh", msrcryptoEcdh.generateKey );
    operations.register( "deriveBits", "ecdh", msrcryptoEcdh.deriveBits );
    operations.register( "deriveKey", "ecdh", msrcryptoEcdh.deriveKey );
}
