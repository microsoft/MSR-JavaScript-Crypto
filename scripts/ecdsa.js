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

var msrcryptoEcdsa = function(curve) {

    var btd = cryptoMath.bytesToDigits,
        dtb = cryptoMath.digitsToBytes,
        ecop = new cryptoECC.EllipticCurveOperatorFp(curve),
        orderByteLength = dtb(curve.order).length,
        tedCurve = curve.type === 1;

    function createKey(privateKeyBytes) {
        return createKeyInternal(btd(privateKeyBytes));
    }

    function createKeyInternal(privateKeyDigits) {

        var publicKey = curve.allocatePointStorage();

        ecop.scalarMultiply(privateKeyDigits, curve.generator, publicKey);

        return {
            publicKey: publicKey,
            privateKey: privateKeyDigits
        };
    }

    function generateKey(randomBytes) {

        var privateKey = [];

        if (!randomBytes) {
            randomBytes = msrcryptoPseudoRandom.getBytes(
                    curve.order.length * cryptoMath.DIGIT_NUM_BYTES);
        }

        cryptoMath.reduce(
            cryptoMath.bytesToDigits(randomBytes),
            curve.order,
            privateKey);

        return createKeyInternal(privateKey);
    }

    function getDigest(messageBytes) {

        // if the message length is longer than the curve-order, truncate.
        if (messageBytes.length > orderByteLength) {
            messageBytes.length = orderByteLength;
        }

        var digest = btd(messageBytes);

        if (tedCurve) {
            var shift = 8 - curve.rbits % 8;
            cryptoMath.shiftRight(digest, digest, shift);
        }

        cryptoMath.reduce(digest, curve.order, digest);

        return digest;
    }

    function sign(privateKey, messageBytes, /*@optional*/ ephemeralKey) {

        if (!ephemeralKey) {
            ephemeralKey = generateKey();
        }

        var r = ephemeralKey.publicKey.x,
            k = ephemeralKey.privateKey,
            d = btd(privateKey.d),
            digest = getDigest(messageBytes.slice()),
            s = [],
            tmp = [],
            signature = null;

        cryptoMath.reduce(r, curve.order, r);
        cryptoMath.modMul(r, d, curve.order, s);
        cryptoMath.add(s, digest, s);
        cryptoMath.reduce(s, curve.order, s);
        cryptoMath.modInvCT(k, curve.order, tmp);
        cryptoMath.modMul(s, tmp, curve.order, s);

        // ensure the bytes arrays are of the expected size
        var rBytes = msrcryptoUtilities.padFront(dtb(r, true, orderByteLength), 0, orderByteLength);
        var sBytes = msrcryptoUtilities.padFront(dtb(s, true, orderByteLength), 0, orderByteLength);

        signature = rBytes.concat(sBytes);

        return signature;
    }

    function verify(publicKey, signatureBytes, messageBytes) {

        var split = Math.floor(signatureBytes.length / 2),
            r = btd(signatureBytes.slice(0, split)),
            s = btd(signatureBytes.slice(split)),
            digest = getDigest(messageBytes.slice()),
            u1 = [],
            u2 = [];

        var publicPoint = new cryptoECC.EllipticCurvePointFp(
            curve, false, btd(publicKey.x), btd(publicKey.y), null, false);

        cryptoMath.modInv(s, curve.order, s);
        cryptoMath.modMul(digest, s, curve.order, u1);
        cryptoMath.modMul(r, s, curve.order, u2);

        var r0 = curve.allocatePointStorage();
        var r1 = curve.allocatePointStorage();

        if (tedCurve) {
            cryptoMath.add(u1, u1, u1);
            cryptoMath.add(u1, u1, u1);
            cryptoMath.reduce(u1, curve.order, u1);
            ecop.scalarMultiply(u1, curve.generator, r0, false);
            ecop.scalarMultiply(u2, publicPoint, r1, false);
            ecop.convertToExtendedProjective(r0);
            ecop.convertToExtendedProjective(r1);
            ecop.add(r1, r0, r0);
            ecop.normalize(r0);

        } else {
            ecop.scalarMultiply(u1, curve.generator, r0);
            ecop.scalarMultiply(u2, publicPoint, r1);
            ecop.convertToJacobianForm(r0);
            ecop.convertToMontgomeryForm(r0);
            ecop.convertToMontgomeryForm(r1);
            ecop.mixedAdd(r0, r1, r0);
            ecop.convertToAffineForm(r0);
            ecop.convertToStandardForm(r0);
        }

        if (r0.isInfinity) {
            return false;
        }

        cryptoMath.reduce(r0.x, curve.order, r0.x);

        return cryptoMath.compareDigits(r0.x, r) === 0;
    }

    return {
        createKey: createKey,
        generateKey: generateKey,
        sign: sign,
        verify: verify
    };

};

if (typeof operations !== "undefined") {

    msrcryptoEcdsa.sign = function(p) {

        msrcryptoUtilities.checkParam(p.algorithm.hash, "Object", "algorithm.hash");
        msrcryptoUtilities.checkParam(p.algorithm.hash.name, "String", "algorithm.hash.name");
        msrcryptoUtilities.checkParam(p.keyHandle.algorithm.namedCurve, "String", "p.keyHandle.algorithm.namedCurve");

        var hashName = p.algorithm.hash.name,
            curve = cryptoECC.createCurve(p.keyHandle.algorithm.namedCurve.toUpperCase()),
            hashFunc = msrcryptoHashFunctions[hashName.toUpperCase()](),
            digest = hashFunc.computeHash(p.buffer);

        var ecdsa = msrcryptoEcdsa(curve);

        return ecdsa.sign(p.keyData, digest);
    };

    msrcryptoEcdsa.verify = function(p) {

        var hashName = p.algorithm.hash.name,
            curve = cryptoECC.createCurve(p.keyHandle.algorithm.namedCurve.toUpperCase()),
            hashFunc = msrcryptoHashFunctions[hashName.toUpperCase()](),
            digest = hashFunc.computeHash(p.buffer);

        var ecdsa = msrcryptoEcdsa(curve);

        return ecdsa.verify(p.keyData, p.signature, digest);
    };

    msrcryptoEcdsa.generateKey = function(p) {

        var curve = cryptoECC.createCurve(p.algorithm.namedCurve.toUpperCase());

        var ecdsa = msrcryptoEcdsa(curve);

        var keyPairData = ecdsa.generateKey();

        var dtb = cryptoMath.digitsToBytes;

        // Sometimes the result is a byte short because the byte-conversion
        // trims leading zeros. We pad the zeros back on if needed.
        function padTo8BytesIncrement( array ) {
            return array;
            //return msrcryptoUtilities.padFront(array, 0, Math.ceil(array.length / 8) * 8);
        }
        var x = padTo8BytesIncrement(dtb(keyPairData.publicKey.x));
        var y = padTo8BytesIncrement(dtb(keyPairData.publicKey.y));
        var d = padTo8BytesIncrement(dtb(keyPairData.privateKey));

        return {
            type: "keyPairGeneration",
            keyPair: {
                publicKey: {
                    keyData: {
                        x: x,
                        y: y
                    },
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: ["verify"],
                        type: "public"
                    }
                },
                privateKey: {
                    keyData: {
                        x: x,
                        y: y,
                        d: d
                    },
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: ["sign"],
                        type: "private"
                    }
                }
            }
        };

    };

    msrcryptoEcdsa.importKey = function(p) {

        if (p.format === "raw") {

            // raw key will be public only it the form:
            // 4 | <x data bytes> | <y data bytes>

            var keyData = p.keyData;

            if (keyData[0] !== 4) { throw new Error("DataError"); }

            // tslint:disable-next-line: no-bitwise
            var elementSize = ~~((keyData.length - 1) / 2);

            var curveName = p.algorithm.namedCurve.toUpperCase();

            var x = keyData.slice(1, elementSize + 1),
                y = keyData.slice(elementSize + 1);

            if (cryptoECC.validatePoint(curveName, x, y) === false) {
                throw new Error("DataError");
            }

            return {
                type: "keyImport",
                keyData: { x: x, y: y },
                keyHandle: {
                    algorithm: p.algorithm,
                    extractable: p.extractable,
                    usages: p.usages,
                    type: "public"
                }
            };
        }

        if ( p.format === "jwk" ) {
            var keyObject = msrcryptoJwk.jwkToKey( p.keyData, p.algorithm, ["x", "y", "d", "crv"] );

            // If only private key data 'd' is imported, create x and y
            if ( keyObject.d && ( !keyObject.x || !keyObject.y ) ) {

                var curve = msrcryptoEcdsa.curves[p.algorithm.namedCurve]();

                var ecdsa = msrcryptoEcdsa( curve );

                var publicKey = ecdsa.computePublicKey( keyObject.d );

                keyObject.x = publicKey.x;
                keyObject.y = publicKey.y;
            }

            if (cryptoECC.validatePoint(p.algorithm.namedCurve.toUpperCase(), keyObject.x, keyObject.y) === false) {
                throw new Error("DataError");
            }

            return {
                type: "keyImport",
                keyData: keyObject,
                keyHandle: {
                    algorithm: p.algorithm,
                    extractable: p.extractable || keyObject.extractable,
                    usages: null || p.usages, // IE11 returns null here
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

    };

    msrcryptoEcdsa.exportKey = function(p) {
        var EC_PUBLICKEY  = "1.2.840.10045.2.1";
        var curveOid = {
            "P-256" : "1.2.840.10045.3.1.7 ", //PRIME256V1
            "P-384" : "1.3.132.0.34", //SECP384R1
            "P-521" : "1.3.132.0.35" //SECP521R1
        }

        if (p.format === "raw" && p.keyHandle.type === "public") {

            var keyData = [4].concat(p.keyData.x, p.keyData.y);

            return { type: "keyExport", keyHandle: keyData };
        }

        if (p.format === "jwk") {
            var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);
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

        throw new Error("unsupported export format.");

    };

    operations.register("sign", "ECDSA", msrcryptoEcdsa.sign);
    operations.register("verify", "ECDSA", msrcryptoEcdsa.verify);
    operations.register("generateKey", "ECDSA", msrcryptoEcdsa.generateKey);
    operations.register("importKey", "ECDSA", msrcryptoEcdsa.importKey);
    operations.register("exportKey", "ECDSA", msrcryptoEcdsa.exportKey);
}
