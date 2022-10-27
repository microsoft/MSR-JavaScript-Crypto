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

/// The "concat" key derivation function from NIST SP-800-56A.
var msrcryptoPbkdf2 = (function() {

    //function deriveBits(algorithm, keyBytes, bits) {
    function deriveBits(p) {

        var algorithm = p.algorithm,
            keyBytes = p.keyData,
            bits = p.length,
            iterations = algorithm.iterations,
            saltBytes = Array.apply(null, algorithm.salt),
            byteLen = Math.ceil(bits / 8),
            hLen,
            blockCount,
            output = [];

        switch (algorithm.hash.name.toUpperCase()) {
            case "SHA-1": hLen = 20; break;
            case "SHA-256": hLen = 32; break;
            case "SHA-384": hLen = 48; break;
            case "SHA-512": hLen = 64; break;
            default: throw new Error("Unsupported hash algorithm");
        }

        // 1. If dkLen > (2 ^ 32 - 1) * hLen, output "derived key too long"

        // TODO: allow non-8 bit lengths
        blockCount = Math.ceil(byteLen / hLen);

        var hmacKey = msrcryptoHmac.importKey({
            format: "raw",
            keyData: keyBytes,
            algorithm: {
                name: "HMAC",
                hash: algorithm.hash
            }
        });

        var hmacContext = {
            algorithm: algorithm,
            keyHandle: hmacKey.keyHandle,
            keyData: hmacKey.keyData,
            workerid: 0,
            buffer: null
        };

        function F(/*P,*/ S, c, i) {

            var result = [],
                // tslint:disable-next-line: no-bitwise
                u = S.concat([i >>> 24 & 0xFF, i >>> 16 & 0xFF, i >>> 8 & 0xFF, i & 0xFF]);

            for (var j = 0; j < c; j++) {
                hmacContext.buffer = u;
                u = msrcryptoHmac.signHmac(hmacContext);
                for (var k = 0; k < hLen; k++) {
                    // tslint:disable-next-line: no-bitwise
                    result[k] = ~~result[k] ^ u[k];
                }
            }

            return result;
        }

        for (var block = 1; block <= blockCount; block++) {
            output = output.concat(F(saltBytes, iterations, block));
        }

        output.length = byteLen;

        return output;
    }

    return {

        deriveBits: deriveBits

    };

}());

var msrcryptoKdfInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoPbkdf2.importKey = function(p) {
        var keyData;

        if (p.format === "raw") {
            keyData = msrcryptoUtilities.toArray(p.keyData);
        } else {
            throw new Error("unsupported import format");
        }

        if (p.extractable !== false) {
            throw new Error("only extractable=false is supported.");
        }

        return {
            type: "keyImport",
            keyData: keyData,
            keyHandle: new MsrCryptoKey({
                algorithm: { name: "PBKDF2" },
                extractable: false,
                usages: p.usages,
                type: "secret"
            })
        };

    };

    operations.register("deriveBits", "PBKDF2", msrcryptoPbkdf2.deriveBits);
    operations.register("importKey", "PBKDF2", msrcryptoPbkdf2.importKey);
}
