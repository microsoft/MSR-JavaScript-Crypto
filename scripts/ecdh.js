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

        try {

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
                        extractable: p.extractable || false,
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

            if ( p.format === "spki" ) {

                var lengths = {
                    "P-256" : 32,
                    "P-384" : 48,
                    "P-521" : 66 
                }

                var partLen = lengths[p.algorithm.namedCurve];

                var privateKeyInfo = asn1.parse(p.keyData);

                if (privateKeyInfo == null) {
                    throw new Error("invalid key data.");
                }

                var bitString = privateKeyInfo[1];

                // +1 to skip the leading zero that will always be there if the bitstring contains a sequence.
                var keySequence = bitString.data.slice(bitString.header + 1);

                if (keySequence == null || keySequence.shift() !== 4 || keySequence.length !== partLen * 2) {
                    throw new Error("invalid key data.");
                }

                var x = keySequence.slice(0, partLen),
                    y = keySequence.slice(partLen)

                if (!msrcryptoUtilities.isBytes(x) || !msrcryptoUtilities.isBytes(y)) {
                    throw new Error("invalid key data.");
                }

                var keyObject = {x:x, y:y};

                if ( cryptoECC.validatePoint( p.algorithm.namedCurve.toUpperCase( ), keyObject.x, keyObject.y ) === false ) {
                    throw new Error( "DataError" );
                }

                return {
                    type: "keyImport",
                    keyData: keyObject,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: p.usages,
                        type: "public"
                    }
                };

            }

            if ( p.format === "pkcs8" ) {

                var lengths = {
                    "P-256" : 32,
                    "P-384" : 48,
                    "P-521" : 66 
                }

                var partLen = lengths[p.algorithm.namedCurve];

                var privateKeyInfo = asn1.parse(p.keyData);

                if (privateKeyInfo == null) {
                    throw new Error("invalid key data.");
                }

                var octetString = privateKeyInfo[2];
                var keySequence = asn1.parse(octetString.data.slice(octetString.header));

                if (keySequence == null) {
                    throw new Error("invalid key data.");
                }

                var d = keySequence[1].data.slice(keySequence[1].header);

                var bitString = asn1.parse(keySequence[2][0].data);

                var keySequence = bitString.data.slice(bitString.header + 1);

                if (keySequence == null || keySequence.shift() !== 4 || keySequence.length !== partLen * 2) {
                    throw new Error("invalid key data.");
                }

                var x = keySequence.slice(0, partLen),
                    y = keySequence.slice(partLen)

                if (!msrcryptoUtilities.isBytes(x) || !msrcryptoUtilities.isBytes(y)) {
                    throw new Error("invalid key data.");
                }

                var keyObject = {x:x, y:y, d:d};

                if ( cryptoECC.validatePoint( p.algorithm.namedCurve.toUpperCase( ), keyObject.x, keyObject.y ) === false ) {
                    throw new Error( "DataError" );
                }

                return {
                    type: "keyImport",
                    keyData: keyObject,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: p.usages,
                        type: "private"
                    }
                };

            }

        } catch(err) {
            throw new msrcryptoUtilities.error("DataError", "");
        }

    };

    msrcryptoEcdh.exportKey = function( p ) {
        var EC_PUBLICKEY  = "1.2.840.10045.2.1";
        var curveOid = {
            "P-256" : "1.2.840.10045.3.1.7 ", //PRIME256V1
            "P-384" : "1.3.132.0.34", //SECP384R1
            "P-521" : "1.3.132.0.35" //SECP521R1
        }

        if ( p.format === "raw" && p.keyHandle.type === "public" ) {

            var keyData = [4].concat( p.keyData.x, p.keyData.y );

            return { type: "keyExport", keyHandle: keyData };
        }

        if ( p.format === "jwk" ) {
            var jsonKeyStringArray = msrcryptoJwk.keyToJwk( p.keyHandle, p.keyData );
            return { type: "keyExport", keyHandle: jsonKeyStringArray };
        }

        if (p.format === "spki") {
            var bytes = asn1.encode({
                SEQUENCE: [
                    {
                        SEQUENCE: [
                            { "OBJECT IDENTIFIER": EC_PUBLICKEY }, 
                            { "OBJECT IDENTIFIER": curveOid[p.algorithm.namedCurve] }
                        ],
                    },
                    {
                        "BIT STRING": [4].concat(p.keyData.x, p.keyData.y)
                    },
                ],
            });

            return { type: "keyExport", keyHandle: bytes };
        }

        if (p.format === "pkcs8") {
            var bytes = asn1.encode({
                SEQUENCE: [
                    { INTEGER: 0 },
                    {
                        SEQUENCE: [
                            { "OBJECT IDENTIFIER": EC_PUBLICKEY },
                            { "OBJECT IDENTIFIER": curveOid[p.algorithm.namedCurve] },
                        ],
                    },
                    {
                        "OCTET STRING": {
                            SEQUENCE: [
                                { INTEGER: 1 },
                                { "OCTET STRING": p.keyData.d },
                                {
                                    APPLICATION: [
                                        {"BIT STRING": [4].concat(p.keyData.x, p.keyData.y)},
                                    ],
                                    tag : 1
                                },
                            ],
                        },
                    },
                ],
            });

            return { type: "keyExport", keyHandle: bytes };
        }

        throw new Error( "unsupported export format." );
    };

    operations.register( "importKey", "ECDH", msrcryptoEcdh.importKey );
    operations.register( "exportKey", "ECDH", msrcryptoEcdh.exportKey );
    operations.register( "generateKey", "ECDH", msrcryptoEcdh.generateKey );
    operations.register( "deriveBits", "ECDH", msrcryptoEcdh.deriveBits );
    operations.register( "deriveKey", "ECDH", msrcryptoEcdh.deriveKey );
}
