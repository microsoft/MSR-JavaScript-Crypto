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

var msrcryptoAESKW = function (blockCipher) {
    function encrypt(buffer) {
        // Inputs:  Plaintext, n 64-bit values {P1, P2, ..., Pn}, and
        // Key, K (the KEK).
        // Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.

        var plain = [[0]];
        for (var i = 0; i < buffer.length; i += 8) {
            plain.push(buffer.slice(i, i + 8));
        }

        // 1) Initialize variables.
        //     Set A = IV, an initial value (see 2.2.3)
        //     For i = 1 to n
        //         R[i] = P[i]

        var A = [166, 166, 166, 166, 166, 166, 166, 166]; // A = IV = A6A6A6A6A6A6A6A6
        var n = plain.length - 1;
        var registers = [];

        for (var i = 1; i <= n; i++) {
            registers[i] = plain[i];
        }

        // 2) Calculate intermediate values.
        //     For j = 0 to 5
        //         For i=1 to n
        //             B = AES(K, A | R[i])
        //             A = MSB(64, B) ^ t where t = (n*j)+i
        //             R[i] = LSB(64, B)

        for (var j = 0; j <= 5; j++) {
            for (var i = 1; i <= n; i++) {
                var t = n * j + i;

                var enc = blockCipher.encrypt(A.concat(registers[i]));

                registers[i] = enc.slice(8);

                A = enc.slice(0, 8);
                for (var ai = 7; t > 0; ai--, t >>>= 8) {
                    A[ai] ^= t & 255;
                }
            }
        }

        // 3) Output the results.
        //     Set C[0] = A
        //     For i = 1 to n
        //         C[i] = R[i]
        var C = A;
        for (var i = 1; i <= n; i++) {
            C = C.concat(registers[i]);
        }

        return C;
    }

    function decrypt(buffer) {
        var cipher = [];
        for (var i = 0; i < buffer.length; i += 8) {
            cipher.push(buffer.slice(i, i + 8));
        }

        var n = cipher.length - 1;
        var registers = [];
        var plain = [];

        // 1) Initialize variables.
        //     Set A = C[0]
        //     For i = 1 to n
        //         R[i] = C[i]
        var A = cipher[0];
        for (var i = 1; i <= n; i++) {
            registers[i] = cipher[i];
        }

        // 2) Compute intermediate values.
        //     For j = 5 to 0
        //         For i = n to 1
        //             B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
        //             A = MSB(64, B)
        //             R[i] = LSB(64, B)
        for (var j = 5; j >= 0; j--) {
            for (var i = n; i >= 1; i--) {
                var t = n * j + i;
                for (var ai = 7; t > 0; ai--, t >>>= 8) {
                    A[ai] ^= t & 255;
                }
                var B = blockCipher.decrypt(A.concat(registers[i]));
                A = B.slice(0, 8);
                registers[i] = B.slice(8);
            }
        }

        if (A.join(",") !== "166,166,166,166,166,166,166,166") {
            throw msrcryptoUtilities.error("OperationError", "");
        }

        for (var i = 1; i <= n; i++) {
            plain = plain.concat(registers[i]);
        }

        return plain;
    }

    return {
        encrypt: encrypt,
        decrypt: decrypt
    };
};

if (typeof operations !== "undefined") {
    var aeskwInstances = {};

    msrcryptoAESKW.workerEncrypt = function (p) {
        var result,
            id = p.workerid;

        if (p.buffer.length % 8 !== 0) {
            throw msrcryptoUtilities.error(
                "DataError",
                "The AES-KW input data length is invalid: not a multiple of 8 bytes"
            );
        }

        if (!aeskwInstances[id]) {
            aeskwInstances[id] = msrcryptoAESKW(msrcryptoBlockCipher.aes(p.keyData));
        }

        result = aeskwInstances[id].encrypt(p.buffer);
        aeskwInstances[id] = null;
        return result;
    };

    msrcryptoAESKW.workerDecrypt = function (p) {
        var result,
            id = p.workerid;

        if (p.buffer.length % 8 !== 0) {
            throw msrcryptoUtilities.error(
                "DataError",
                "The AES-KW input data length is invalid: not a multiple of 8 bytes"
            );
        }

        if (!aeskwInstances[id]) {
            aeskwInstances[id] = msrcryptoAESKW(msrcryptoBlockCipher.aes(p.keyData));
        }

        result = aeskwInstances[id].decrypt(p.buffer);
        aeskwInstances[id] = null;
        return result;
    };

    msrcryptoAESKW.generateKey = function (p) {
        if (p.algorithm.length % 8 !== 0) {
            throw msrcryptoUtilities.error("OperationError", "AES key length must be 128, 192, or 256 bits");
        }

        return {
            type: "keyGeneration",
            keyData: msrcryptoPseudoRandom.getBytes(Math.floor(p.algorithm.length / 8)),
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable,
                usages: null || p.usages,
                type: "secret"
            }
        };
    };

    msrcryptoAESKW.importKey = function (p) {
        var keyObject;
        var keyBits = p.keyData.length * 8;

        if (p.format === "jwk") {
            keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);
        } else if (p.format === "raw") {
            if (keyBits !== 128 && keyBits !== 192 && keyBits !== 256) {
                throw msrcryptoUtilities.error("OperationError", "AES key length must be 128, 192, or 256 bits");
            }
            keyObject = { k: msrcryptoUtilities.toArray(p.keyData) };
        } else {
            throw new TypeError("Invalid keyFormat argument");
        }

        p.algorithm.length = keyObject.k.length * 8;

        return {
            keyData: keyObject.k,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                usages: null || p.usages,
                type: "secret"
            },
            type: "keyImport"
        };
    };

    msrcryptoAESKW.exportKey = function (p) {
        if (p.format === "jwk") {
            return { type: "keyExport", keyHandle: msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData) };
        }

        if (p.format === "raw") {
            return { type: "keyExport", keyHandle: p.keyData };
        }

        throw new TypeError("Invalid keyFormat argument");
    };

    operations.register("importKey", "AES-KW", msrcryptoAESKW.importKey);
    operations.register("exportKey", "AES-KW", msrcryptoAESKW.exportKey);
    operations.register("generateKey", "AES-KW", msrcryptoAESKW.generateKey);
    operations.register("encrypt", "AES-KW", msrcryptoAESKW.workerEncrypt);
    operations.register("decrypt", "AES-KW", msrcryptoAESKW.workerDecrypt);
}
