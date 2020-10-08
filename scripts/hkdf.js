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

/// The HKDF key derivation function from https://tools.ietf.org/html/rfc5869.
var msrcryptoHKDF = (function() {

    //function deriveBits(algorithm, keyBytes, bits) {
    function deriveBits(p) {
        var utils = msrcryptoUtilities;

        var algorithm = p.algorithm,
            ikmBytes = p.keyData,
            bits = p.length,
            byteLen = Math.ceil(bits / 8),
            // utils.toArray is more complete than Array.apply see implementation for details
            infoBytes = utils.toArray(algorithm.info),
            saltBytes = utils.toArray(algorithm.salt || utils.getVector(byteLen)),
            hLen,
            memo = [];

        switch (algorithm.hash.name.toUpperCase()) {
            case "SHA-1": hLen = 20; break;
            case "SHA-256": hLen = 32; break;
            case "SHA-384": hLen = 48; break;
            case "SHA-512": hLen = 64; break;
            default: throw new Error("Unsupported hash algorithm");
        }

        // (<= 255*HashLen) from https://tools.ietf.org/html/rfc5869
        if (byteLen > 255 * hLen) throw new Error('Can not derive keys larger than ' + 255 * hLen)

        // Import the saltBytes to preform the extract step
        var baseKey = msrcryptoHmac.importKey({
            format: "raw",
            keyData: saltBytes,
            algorithm: {
                name: "HMAC",
                hash: algorithm.hash
            }
        });

        var hmacContext = {
            algorithm: algorithm,
            keyHandle: baseKey.keyHandle,
            keyData: baseKey.keyData,
            workerid: 0,
            buffer: ikmBytes
        };

        // Extract the prk from ikm and salt.
        var prk = msrcryptoHmac.signHmac(hmacContext);
        var prkKey = msrcryptoHmac.importKey({
            format: "raw",
            keyData: prk,
            algorithm: {
                name: "HMAC",
                hash: algorithm.hash
            }
        });

        // Expand step
        var N = Math.ceil(byteLen / hLen);
        /* L/length octets are returned from T(1)...T(N),
         * and T(0) is definitionally empty/zero length.
         * Elide T(0) into the [] case
         * and then return L octets of T indexed 0...L-1.
         */
        for (let i = 0; i < N; i++) {
          memo[i] = msrcryptoHmac.signHmac({
            algorithm: algorithm,
            keyHandle: prkKey.keyHandle,
            keyData: prkKey.keyData,
            workerid: 0,
            buffer: [].concat(
                    // The || [] is for i === 0
                    memo[i - 1] || [],
                    infoBytes,
                    i+1
                )
            });
        }

        // Slice the appropriate byte length
        return [].concat.apply([], memo).slice(0, byteLen)
    }

    return {

        deriveBits: deriveBits

    };

}());

var msrcryptoKdfInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoHKDF.importKey = function(p) {
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
            keyHandle: {
                algorithm: { name: "HKDF" },
                extractable: false,
                usages: p.usages,
                type: "secret"
            }
        };

    };

    operations.register("deriveBits", "HKDF", msrcryptoHKDF.deriveBits);
    operations.register("importKey", "HKDF", msrcryptoHKDF.importKey);
}
