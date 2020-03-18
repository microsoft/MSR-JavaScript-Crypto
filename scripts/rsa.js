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
        case "rsassa-pkcs1-v1_5":
            checkHash();
            padding = rsaMode.pkcs1Sign(keyStruct, hashFunction);
            break;

        case "rsa-oaep":
            checkHash();
            padding = rsaMode.oaep(keyStruct, hashFunction);
            break;

        case "rsa-pss":
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
            hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()](),
            saltLength = p.algorithm.saltLength,
            salt = p.algorithm.salt;

        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);

        return rsaObj.signData(p.buffer, saltLength, salt);
    };

    msrcryptoRsa.verify = function(/*@dynamic*/ p) {
        var hashName = p.keyHandle.algorithm.hash.name,
            hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()](),
            rsaObj,
            saltLength = p.algorithm.saltLength;

        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);

        return rsaObj.verifySignature(p.signature, p.buffer, saltLength);
    };

    msrcryptoRsa.workerEncrypt = function(/*@dynamic*/ p) {
        var result, rsaObj, hashFunc, hashName;

        switch (p.algorithm.name) {
            case "rsa-oaep":
                hashName = p.keyHandle.algorithm.hash.name; // hash is on key alg
                if (!hashName) {
                    throw new Error("unsupported hash algorithm");
                }
                hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()]();
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
            case "rsa-oaep":
                var hashName = p.keyHandle.algorithm.hash.name; // hash is on key alg
                if (!hashName) {
                    throw new Error("unsupported hash algorithm");
                }
                hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()]();
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

            keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["n", "e", "d", "q", "p", "dq", "dp", "qi"]);

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

            var bitString = publicKeyInfo[1];
            // +1 to skip the leading zero that will always be there if the bitstring contains a sequence.
            var keySequence = asn1.parse(bitString.data.slice(bitString.header + 1), true);

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

        } else {
            throw new Error("unsupported key import format.");
        }

        return {
            type: "keyImport",
            keyData: keyObject,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable,
                usages: p.usages, // IE11 returns null here
                type: keyObject.d || keyObject.dq ? "private" : "public"
            }
        };
    };

    msrcryptoRsa.exportKey = function(/*@dynamic*/ p) {
        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };
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

        // create a MongomeryMultiplier and attach to this private key
        var pk = keyPair.privateKey;
        pk.ctxp = (new cryptoMath.MontgomeryMultiplier(b2d(pk.p))).ctx;
        pk.ctxq = (new cryptoMath.MontgomeryMultiplier(b2d(pk.q))).ctx;

        var algName = p.algorithm.name;
        var rsaKeyType = algName.slice(algName.indexOf("-") + 1).toLowerCase();

        var publicUsage = rsaKeyType === "oaep" ? ["encrypt"] : ["verify"];
        var privateUsage = rsaKeyType === "oaep" ? ["decrypt"] : ["sign"];

        return {
            type: "keyGeneration",
            keyPair: {
                publicKey: {
                    keyData: keyPair.publicKey,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: null || publicUsage,
                        type: "public"
                    }
                },
                privateKey: {
                    keyData: keyPair.privateKey,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: null || privateUsage,
                        type: "private"
                    }
                }
            }
        };
    };

    operations.register("sign", "rsassa-pkcs1-v1_5", msrcryptoRsa.sign);
    operations.register("sign", "rsa-pss", msrcryptoRsa.sign);

    operations.register("verify", "rsassa-pkcs1-v1_5", msrcryptoRsa.verify);
    operations.register("verify", "rsa-pss", msrcryptoRsa.verify);

    operations.register("encrypt", "rsa-oaep", msrcryptoRsa.workerEncrypt);
    operations.register("decrypt", "rsa-oaep", msrcryptoRsa.workerDecrypt);

    operations.register("importKey", "rsa-oaep", msrcryptoRsa.importKey);
    operations.register("importKey", "rsassa-pkcs1-v1_5", msrcryptoRsa.importKey);
    operations.register("importKey", "rsa-pss", msrcryptoRsa.importKey);

    operations.register("exportKey", "rsa-oaep", msrcryptoRsa.exportKey);
    operations.register("exportKey", "rsassa-pkcs1-v1_5", msrcryptoRsa.exportKey);
    operations.register("exportKey", "rsa-pss", msrcryptoRsa.exportKey);

    operations.register("generateKey", "rsa-oaep", msrcryptoRsa.generateKeyPair);
    operations.register("generateKey", "rsassa-pkcs1-v1_5", msrcryptoRsa.generateKeyPair);
    operations.register("generateKey", "rsa-pss", msrcryptoRsa.generateKeyPair);
}
