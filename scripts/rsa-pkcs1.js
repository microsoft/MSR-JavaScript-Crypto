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

var rsaMode = rsaMode || {};
rsaMode.pkcs1Sign = function(keyStruct, hashFunction) {

    var utils = msrcryptoUtilities,
        size = keyStruct.n.length;

    function emsa_pkcs1_v15_encode(messageBytes) {

        var paddedData,
            hash,
            tlen;

        hash = hashFunction.computeHash(messageBytes.slice());

        paddedData = hashFunction.der.concat(hash);

        tlen = paddedData.length;

        if (size < tlen + 11) {
            throw new Error("intended encoded message length too short");
        }

        return [0x00, 0x01].concat(
            utils.getVector(size - tlen - 3, 0xFF),
            [0],
            paddedData);
    }

    return {

        sign: function(messageBytes) {
            return emsa_pkcs1_v15_encode(messageBytes);
        },

        verify: function(signatureBytes, messageBytes) {
            var emp = emsa_pkcs1_v15_encode(messageBytes);

            return utils.arraysEqual(signatureBytes, emp);

        }
    };
};
