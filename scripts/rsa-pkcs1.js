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

rsaMode.pkcs1Encrypt = function(keyStruct) {

    var random = msrcryptoPseudoRandom,
        size = keyStruct.n.length;

    function pad(data) {

        var randomness;

        if (data.length > size - 11) {
            throw new Error("message too long");
        }

        // A minimum of 8 random bytes
        randomness = random.getNonZeroBytes(size - data.length - 3);

        return [0, 2].concat(randomness, [0], data);
    }

    function validatePadding(paddedData) {
        // Validate the padding:
        //   we cannot know how much padding there should be.
        //   we can know that:
        //     a. the first two bytes should be 0,2
        //     b. the next eight bytes are non-zero

        // validate first 2 bytes of padding are 0, 2
        var paddingValid = paddedData[0] === 0 && paddedData[1] === 2;

        // verify no zeros from bytes 2-10
        for (var i = 2; i < 10; i++) {
            paddingValid = paddingValid && !!paddedData[i];
        }

        return paddingValid;
    }

    function unpad(paddedData) {

        var i,
            paddingIsValid = validatePadding(paddedData),
            startOfData = 0;

        for (i = 1; i < paddedData.length; i += 1) {
            // scan data for first zero byte
            startOfData = startOfData || +!paddedData[i] && i + 1;
        }

        startOfData = (-paddingIsValid && startOfData);

        return {
            data: paddedData.slice(startOfData),
            valid: paddingIsValid
        };
    }

    return {

        pad: function(messageBytes) {
            return pad(messageBytes);
        },

        unpad: function(encodedBytes) {
            return unpad(encodedBytes);
        }
    };

};

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
