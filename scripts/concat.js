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

/// key derivation function from RFC 5869A https://www.ietf.org/rfc/rfc5869.txt
var msrcryptoConcatKdf = (function () {

    function deriveBits(p) {

        var hashName = p.algorithm.hash.name,
            hashFunction = msrcryptoHashFunctions[hashName.toUpperCase()](),
            alg = p.algorithm;

        var otherInfo =
            utils.toArray(alg.algorithmId).concat(
                utils.toArray(alg.partyUInfo),
                utils.toArray(alg.partyVInfo),
                utils.toArray(alg.publicInfo) || [],
                utils.toArray(alg.privateInfo) || []);

        var reps = Math.ceil(p.length / hashFunction.hashLen),
            counter = 1,
            digest = p.keyData.concat(otherInfo),
            output = [];

        for (var i = 0; i < reps; i++) {
            var data = utils.int32ToBytes(counter++).concat(digest);
            var /*type(Array)*/ h = hashFunction.computeHash(data);
            output = output.concat(h);
        }

        return output.slice(0, p.length / 8);

    }

    return {
        deriveBits: deriveBits
    };

}());

var msrcryptoConcatKdfInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoConcatKdf.importKey = function (p) {
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
                algorithm: { name: "CONCAT" },
                extractable: false,
                usages: p.usages,
                type: "secret"
            })
        };

    };

    operations.register("deriveBits", "CONCAT", msrcryptoConcatKdf.deriveBits);
    operations.register("importKey", "CONCAT", msrcryptoConcatKdf.importKey);
}
