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
var msrcryptoKdf = function(hashFunction) {

    var utils = msrcryptoUtilities;

    function deriveKey(secretBytes, otherInfo, keyOutputLength) {
        /// <summary></summary>
        /// <param name="secretBytes" type="Array"></param>
        /// <param name="otherInfo" type="Array"></param>
        /// <param name="keyOutputLength" type="Number"></param>
        /// <returns type="Array"></returns>

        var reps = Math.ceil(keyOutputLength / (hashFunction.hashLen / 8)),
            counter = 1,
            digest = secretBytes.concat(otherInfo),
            output = [];

        for (var i = 0; i < reps; i++) {

            var data = utils.int32ToBytes(counter++).concat(digest);

            var /*type(Array)*/ h = hashFunction.computeHash(data);

            output = output.concat(h);
        }

        return output.slice(0, keyOutputLength);
    }

    return {

        deriveKey: deriveKey

    };

};

var msrcryptoKdfInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoKdf.deriveKey = function(/*@dynamic*/p) {

        var utils = msrcryptoUtilities;

        var hashName = p.algorithm.hash.name;

        var hashFunction = msrcryptoHashFunctions[hashName.toUpperCase()]();

        msrcryptoKdfInstance = msrcryptoKdf(hashFunction);

        var alg = p.algorithm;

        var otherInfo =
            utils.toArray(alg.algorithmId).concat(
            utils.toArray(alg.partyUInfo),
            utils.toArray(alg.partyVInfo),
            utils.toArray(alg.publicInfo),
            utils.toArray(alg.privateInfo));

        var result =
            msrcryptoKdfInstance.deriveKey(p.keyData, otherInfo, p.derivedKeyType.length);

        msrcryptoKdfInstance = null;

        return {
            type: "keyDerive",
            keyData: result,
            keyHandle: {
                algorithm: p.derivedKeyType,
                extractable: p.extractable,
                usages: null || p.usages,
                type: "secret"
            }
        };

    };

    msrcryptoKdf.deriveBits = function(/*@dynamic*/p) {

        var hashName = p.algorithm.hash.name;

        var hashFunction = msrcryptoHashFunctions[hashName.toUpperCase()]();

        msrcryptoKdfInstance = msrcryptoKdf(hashFunction);

        var alg = p.algorithm;

        var otherInfo =
            alg.algorithmId.concat(
            alg.partyUInfo,
            alg.partyVInfo,
            alg.publicInfo || [],
            alg.privateInfo || []);

        var result =
            msrcryptoKdfInstance.deriveKey(p.keyData, otherInfo, p.length);

        msrcryptoKdfInstance = null;

        return result;

    };

    operations.register("deriveKey", "concat", msrcryptoKdf.deriveKey);
    operations.register("deriveBits", "concat", msrcryptoKdf.deriveBits);

}
