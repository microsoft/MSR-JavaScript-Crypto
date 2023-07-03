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


/// key derivation function from SP800-108 https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
var msrcryptoHkdfCtr = (function () {

    function deriveBits(p) {

        var algorithm = p.algorithm,
            keyBytes = p.keyData,
            bits = p.length,
            labelBytes = algorithm.label,
            contextBytes = algorithm.context,
            byteLen = Math.ceil(bits / 8),
            hLen,
            output = [],
            i,
            hmacContext;

        switch (algorithm.hash.name.toUpperCase()) {
            case "SHA-1": hLen = 20; break;
            case "SHA-256": hLen = 32; break;
            case "SHA-384": hLen = 48; break;
            case "SHA-512": hLen = 64; break;
            default: throw new Error("Unsupported hash algorithm.");
        }

        if (algorithm.label == null) {
            throw new Error("HkdfCtrParams: label: Missing required property.");
        }

        if (algorithm.context == null) {
            throw new Error("HkdfCtrParams: context: Missing required property.");
        }

        if (bits % 8 !== 0) {
            throw new Error("The length provided for HKDF-CTR is not a multiple of 8 bits.");
        }

        if (byteLen > 255 * hLen) {
            throw new Error("The length provided for HKDF-CTR is too large.");
        }

        // if (labelBytes.length === 0) {
        //     labelBytes = msrcryptoUtilities.getVector(hLen);
        // }

        hmacContext = {
            workerid: 0,
            keyHandle: { algorithm: algorithm },
            keyData: keyBytes,
            buffer: keyBytes
        };

        // Label || 0x00 || Context || [L]2
        var fixed = labelBytes.concat([0],contextBytes,utils.int32ToBytes(bits));

        for (i = 1; i <= Math.ceil(byteLen / hLen); i++) {
            hmacContext.buffer = utils.int32ToBytes(i).concat(fixed);
            output = output.concat(msrcryptoHmac.signHmac(hmacContext));
        }

        return output.slice(0, byteLen);
    }

    return {
        deriveBits: deriveBits
    };

}());

if (typeof operations !== "undefined") {

    msrcryptoHkdfCtr.importKey = function (p) {
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
                algorithm: { name: "HKDF-CTR" },
                extractable: false,
                usages: p.usages,
                type: "secret"
            })
        };

    };

    operations.register("deriveBits", "HKDF-CTR", msrcryptoHkdfCtr.deriveBits);
    operations.register("importKey", "HKDF-CTR", msrcryptoHkdfCtr.importKey);
}
