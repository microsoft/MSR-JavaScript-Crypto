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

var msrcryptoRsa = function(keyStruct, mode, /*@optional*/ hashFunction) {
    var rsaBase = msrcryptoRsaBase(keyStruct);

    if (!mode) {
        throw new Error("padding mode");
    }

    function checkHash() {
        if (!hashFunction || !hashFunction.computeHash) {
            throw new Error("missing hash function");
        }
    }

    var paddingFunction = null,
        unPaddingFunction = null;

    var padding;

    switch (mode) {

        case "RSAES-PKCS1-V1_5":
            padding = rsaMode.pkcs1Encrypt(keyStruct);
            break;

        case "RSASSA-PKCS1-V1_5":
            checkHash();
            padding = rsaMode.pkcs1Sign(keyStruct, hashFunction);
            break;

        case "RSA-OAEP":
            checkHash();
            padding = rsaMode.oaep(keyStruct, hashFunction);
            break;

        case "RSA-PSS":
            checkHash();
            padding = rsaMode.pss(keyStruct, hashFunction);
            break;

        case "raw":
            padding = {
                pad: function(mb) {
                    return mb;
                },
                unpad: function(eb) {
                    return eb;
                }
            };
            break;

        default:
            throw new Error("invalid mode");
    }

    if (padding) {
        paddingFunction = padding.pad || padding.sign;
        unPaddingFunction = padding.unpad || padding.verify;
    }

    var returnObj = {
        encrypt: function(/*@type(Array)*/ dataBytes, /*@optional*/ labelBytes) {
            var paddedData;
            var encryptedData;

            if (paddingFunction !== null) {
                // OAEP padding can take two arguments
                ///<disable>JS3053.IncorrectNumberOfArguments</disable>
                paddedData = paddingFunction(dataBytes, labelBytes);
                ///<enable>JS3053.IncorrectNumberOfArguments</enable>
            } else {
                // Slice() has optional arguments
                ///<disable>JS3053.IncorrectNumberOfArguments</disable>
                paddedData = dataBytes.slice();
                ///<enable>JS3053.IncorrectNumberOfArguments</enable>
            }

            encryptedData = rsaBase.encrypt(paddedData);

            return encryptedData;
        },

        decrypt: function(/*@type(Array)*/ cipherBytes, /*@optional*/ labelBytes) {
            var /*@type(Array)*/ decryptedData = rsaBase.decrypt(cipherBytes);

            if (unPaddingFunction !== null) {
                // OAEP padding can take two arguments
                ///<disable>JS3053.IncorrectNumberOfArguments</disable>
                decryptedData = unPaddingFunction(decryptedData, labelBytes);
                ///<enable>JS3053.IncorrectNumberOfArguments</enable>

                if (decryptedData.valid === false) {
                    throw new Error("OperationError");
                }

                decryptedData = decryptedData.data;

            } else {
                decryptedData = decryptedData.slice(0);
            }

            return decryptedData;
        },

        signData: function(/*@type(Array)*/ messageBytes, /*@optional*/ saltLength, /*@optional*/ salt) {
            return rsaBase.decrypt(paddingFunction(messageBytes, saltLength, salt));
        },

        verifySignature: function(
            /*@type(Array)*/ signature,
            /*@type(Array)*/ messageBytes,
            /*@optional   */ saltLength
        ) {
            var decryptedSig = rsaBase.encrypt(signature);

            return unPaddingFunction(decryptedSig, messageBytes, saltLength);
        },

        generateKeyPair: function(bits) {
            var keyPair = genRsaKeyFromRandom(bits);
        },

        mode: mode
    };

    return returnObj;
};

if (typeof operations !== "undefined") {
    msrcryptoRsa.sign = function(/*@dynamic*/ p) {
        var rsaObj,
            hashName = p.keyHandle.algorithm.hash.name,
            hashFunc = msrcryptoHashFunctions[hashName.toUpperCase()](),
            saltLength = p.algorithm.saltLength,
            salt = p.algorithm.salt;

        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);

        return rsaObj.signData(p.buffer, saltLength, salt);
    };

    msrcryptoRsa.verify = function(/*@dynamic*/ p) {
        var hashName = p.keyHandle.algorithm.hash.name,
            hashFunc = msrcryptoHashFunctions[hashName.toUpperCase()](),
            rsaObj,
            saltLength = p.algorithm.saltLength;

        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);

        return rsaObj.verifySignature(p.signature, p.buffer, saltLength);
    };

    msrcryptoRsa.workerEncrypt = function(/*@dynamic*/ p) {
        var result, rsaObj, hashFunc, hashName;

        switch (p.algorithm.name) {

            case "RSAES-PKCS1-V1_5":
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name);
                result = rsaObj.encrypt(p.buffer);
                break;

            case "RSA-OAEP":
                hashName = p.keyHandle.algorithm.hash.name; // hash is on key alg
                if (!hashName) {
                    throw new Error("unsupported hash algorithm");
                }
                hashFunc = msrcryptoHashFunctions[hashName.toUpperCase()]();
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);
                result = rsaObj.encrypt(p.buffer);
                break;

            default:
                throw new Error("unsupported algorithm");
        }

        return result;
    };

    msrcryptoRsa.workerDecrypt = function(/*@dynamic*/ p) {
        var result, rsaObj, hashFunc;

        switch (p.algorithm.name) {

            case "RSAES-PKCS1-V1_5":
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name);
                result = rsaObj.decrypt(p.buffer);
                break;

            case "RSA-OAEP":
                var hashName = p.keyHandle.algorithm.hash.name; // hash is on key alg
                if (!hashName) {
                    throw new Error("unsupported hash algorithm");
                }
                hashFunc = msrcryptoHashFunctions[hashName.toUpperCase()]();
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);
                result = rsaObj.decrypt(p.buffer);
                break;

            default:
                throw new Error("unsupported algorithm");
        }

        return result;
    };

    msrcryptoRsa.importKey = function(/*@dynamic*/ p) {

        var keyObject;

        if (p.format === "jwk") {

            keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["n", "e", "d", "p", "q", "dp", "dq", "qi"]);

            // if a private key, attach a MontgomeryMultiplier(n);
            if (keyObject.d) {
                keyObject.ctxp = new cryptoMath.MontgomeryMultiplier(cryptoMath.bytesToDigits(keyObject.p)).ctx;
                keyObject.ctxq = new cryptoMath.MontgomeryMultiplier(cryptoMath.bytesToDigits(keyObject.q)).ctx;
            }

        } else if (p.format === "spki") {

            var publicKeyInfo = asn1.parse(p.keyData);

            if (publicKeyInfo == null) {
                throw new Error("invalid key data.");
            }

            var octetString = publicKeyInfo[1];
            // +1 to skip the leading zero that will always be there if the bitstring contains a sequence.
            var keySequence = asn1.parse(octetString.data.slice(octetString.header + 1), true);

            if (keySequence == null) {
                throw new Error("invalid key data.");
            }

            var n = keySequence[0],
                e = keySequence[1];

            if (n.type !== "INTEGER" || e.type !== "INTEGER") {
                throw new Error("invalid key data.");
            }

            n = n.data.slice(n.header);
            e = e.data.slice(e.header);

            // asn.1 integer may have a leading zero if the high-order bit is set in the data bytes
            // this is intended to show the number is positive since a high-order bit may imply it's negative.
            // tslint:disable-next-line: no-bitwise
            if (n[0] === 0 && n[1] & 128) { n = n.slice(1); }
            // tslint:disable-next-line: no-bitwise
            if (e[0] === 0 && e[1] & 128) { e = e.slice(1); }

            keyObject = { n: n, e: e };

        } else if (p.format === "pkcs8") {
            var publicKeyInfo = asn1.parse(p.keyData);

            if (publicKeyInfo == null) {
                throw new Error("invalid key data.");
            }

            var octetString = publicKeyInfo[2];
            var keySequence = asn1.parse(octetString.data.slice(octetString.header), true);

            if (keySequence == null) {
                throw new Error("invalid key data.");
            }

            var keyProps = ["n", "e", "d", "p", "q", "dp", "dq", "qi"];
            keyObject = {};

            for (var i = 1; i < keySequence.length; i++) {
                var int = keySequence[i];
                int = int.data.slice(int.header);
                if (int[0] === 0 && int[1] & 128) {
                    int = int.slice(1);
                }
                keyObject[keyProps[i - 1]] = int;
            }
        } else {
            throw new Error("unsupported key import format.");
        }

        return {
            type: "keyImport",
            keyData: keyObject,
            keyHandle: new CryptoKey({
                algorithm: p.algorithm,
                extractable: p.extractable,
                usages: p.usages, // IE11 returns null here
                type: keyObject.d || keyObject.dq ? "private" : "public"
            })
        };
    };

    msrcryptoRsa.exportKey = function(/*@dynamic*/ p) {
        var RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

        if (p.format === "jwk") {
        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);
            return { type: "keyExport", keyHandle: jsonKeyStringArray };
        }

        if (p.format === "spki") {
            var bytes = asn1.encode({
                SEQUENCE: [
                    {
                        SEQUENCE: [{ "OBJECT IDENTIFIER": RSA_ENCRYPTION }, { NULL: 1 }]
                    },
                    {
                        "BIT STRING": {
                            SEQUENCE: [{ INTEGER: p.keyData.n }, { INTEGER: p.keyData.e }]
                        }
                    }
                ]
            });

            return { type: "keyExport", keyHandle: bytes };
        }

        if (p.format === "pkcs8") {
            var bytes = asn1.encode({
                SEQUENCE: [
                    { INTEGER: 0 },
                    {
                        SEQUENCE: [{ "OBJECT IDENTIFIER": RSA_ENCRYPTION }, { NULL: 1 }]
                    },
                    {
                        "OCTET STRING": {
                            SEQUENCE: [
                                { INTEGER: 0 },
                                { INTEGER: p.keyData.n },
                                { INTEGER: p.keyData.e },
                                { INTEGER: p.keyData.d },
                                { INTEGER: p.keyData.p },
                                { INTEGER: p.keyData.q },
                                { INTEGER: p.keyData.dp },
                                { INTEGER: p.keyData.dq },
                                { INTEGER: p.keyData.qi }
                            ]
                        }
                    }
                ]
            });

            return { type: "keyExport", keyHandle: bytes };
        }

        throw new Error(p.format + " not implemented");
    };

    msrcryptoRsa.genRsaKeyFromRandom = function(bits, e) {
        // public exponent
        var exp = e ? cryptoMath.bytesToDigits(e) : [65537];

        do {
            // generate p
            var p = prime.generatePrime(bits / 2);

            // generate q
            var q = prime.generatePrime(bits / 2);

            if (cryptoMath.compareDigits(q, p) > 0) {
                var t = p;
                p = q;
                q = t;
            }

            var n = [];
            cryptoMath.multiply(p, q, n);

            // compute p-1 & q-1
            // tslint:disable-next-line: variable-name
            var p_1 = [];
            cryptoMath.subtract(p, [1], p_1);

            // tslint:disable-next-line: variable-name
            var q_1 = [];
            cryptoMath.subtract(q, [1], q_1);

            // tslint:disable-next-line: variable-name
            var p_1q_1 = [];
            cryptoMath.multiply(p_1, q_1, p_1q_1);

            // gcd(exp, ((q−1)⋅(p−1))) === 1
            var gcd = [];
            cryptoMath.gcd(exp, p_1q_1, gcd);

            var gcdEqual1 = cryptoMath.compareDigits(gcd, cryptoMath.One) === 0;

        } while (!gcdEqual1);

        var d = [];
        cryptoMath.modInv(exp, p_1q_1, d);

        var dp = [];
        cryptoMath.reduce(d, p_1, dp);

        var dq = [];
        cryptoMath.reduce(d, q_1, dq);

        var qi = [];
        cryptoMath.modInv(q, p, qi);

        var d2b = cryptoMath.digitsToBytes;

        return {
            privateKey: {
                n: d2b(n),
                e: d2b(exp),
                d: d2b(d),
                p: d2b(p),
                q: d2b(q),
                dp: d2b(dp),
                dq: d2b(dq),
                qi: d2b(qi)
            },
            publicKey: { n: d2b(n), e: d2b(exp) }
        };
    };

    msrcryptoRsa.generateKeyPair = function(p) {
        if (typeof p.algorithm.modulusLength === "undefined") {
            throw new Error("missing modulusLength");
        }

        var keyPair;
        var b2d = cryptoMath.bytesToDigits;

        switch (p.algorithm.modulusLength) {
            case 1024:
            case 2048:
            case 4096:
                keyPair = msrcryptoRsa.genRsaKeyFromRandom(p.algorithm.modulusLength, p.algorithm.publicExponent);
                break;
            default:
                throw new Error("invalid modulusLength");
        }

        // create a MontgomeryMultiplier and attach to this private key
        var pk = keyPair.privateKey;
        pk.ctxp = (new cryptoMath.MontgomeryMultiplier(b2d(pk.p))).ctx;
        pk.ctxq = (new cryptoMath.MontgomeryMultiplier(b2d(pk.q))).ctx;

        var algName = p.algorithm.name;
        var rsaKeyType = algName.slice(algName.indexOf("-") + 1).toUpperCase();

        var publicUsage, privateUsage;

        if (algName === "RSASSA-PKCS1-V1_5" || algName === "RSA-PSS") {
            publicUsage = ["verify"];
            privateUsage = ["sign"];
        } else { // OAEP, RSAES
            publicUsage = ["encrypt"];
            privateUsage = ["decrypt"];
        }

        return {
            type: "keyGeneration",
            keyPair: {
                publicKey: {
                    keyData: keyPair.publicKey,
                    keyHandle: new CryptoKey({
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: null || publicUsage,
                        type: "public"
                    })
                },
                privateKey: {
                    keyData: keyPair.privateKey,
                    keyHandle: new CryptoKey({
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: null || privateUsage,
                        type: "private"
                    })
                }
            }
        };
    };

    operations.register("sign", "RSASSA-PKCS1-V1_5", msrcryptoRsa.sign);
    operations.register("sign", "RSA-PSS", msrcryptoRsa.sign);

    operations.register("verify", "RSASSA-PKCS1-V1_5", msrcryptoRsa.verify);
    operations.register("verify", "RSA-PSS", msrcryptoRsa.verify);

    operations.register("encrypt", "RSAES-PKCS1-V1_5", msrcryptoRsa.workerEncrypt);
    operations.register("decrypt", "RSAES-PKCS1-V1_5", msrcryptoRsa.workerDecrypt);
    operations.register("encrypt", "RSA-OAEP", msrcryptoRsa.workerEncrypt);
    operations.register("decrypt", "RSA-OAEP", msrcryptoRsa.workerDecrypt);

    operations.register("importKey", "RSA-OAEP", msrcryptoRsa.importKey);
    operations.register("importKey", "RSAES-PKCS1-V1_5", msrcryptoRsa.importKey);
    operations.register("importKey", "RSASSA-PKCS1-V1_5", msrcryptoRsa.importKey);
    operations.register("importKey", "RSA-PSS", msrcryptoRsa.importKey);

    operations.register("exportKey", "RSA-OAEP", msrcryptoRsa.exportKey);
    operations.register("exportKey", "RSAES-PKCS1-V1_5", msrcryptoRsa.exportKey);
    operations.register("exportKey", "RSASSA-PKCS1-V1_5", msrcryptoRsa.exportKey);
    operations.register("exportKey", "RSA-PSS", msrcryptoRsa.exportKey);

    operations.register("generateKey", "RSA-OAEP", msrcryptoRsa.generateKeyPair);
    operations.register("generateKey", "RSAES-PKCS1-V1_5", msrcryptoRsa.generateKeyPair);
    operations.register("generateKey", "RSASSA-PKCS1-V1_5", msrcryptoRsa.generateKeyPair);
    operations.register("generateKey", "RSA-PSS", msrcryptoRsa.generateKeyPair);
}
