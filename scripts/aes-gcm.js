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

// tslint:disable: no-bitwise

var msrcryptoGcm = function(blockCipher) {

    var utils = msrcryptoUtilities;

    var  mBuffer = [],
         mIvBytes,
         mAdditionalBytes,
         mTagLength,
         mJ0,
         mJ0inc,
         mH = blockCipher.encrypt(utils.getVector(16)),
         mGHashState = utils.getVector(16),
         mGHashBuffer = [],
         mCipherText = [],
         mGctrCb,
         mBytesProcessed = 0;

    function ghash(hashSubkey, dataBytes) {

        var blockCount = Math.floor(dataBytes.length / 16),
            dataBlock;

        for (var i = 0; i < blockCount; i++) {
            dataBlock = dataBytes.slice(i * 16, i * 16 + 16);
            mGHashState = blockMultiplication(utils.xorVectors(mGHashState, dataBlock), hashSubkey);
        }

        mGHashBuffer = dataBytes.slice(blockCount * 16);

        return mGHashState;
    }

    function finishGHash() {

        var u = 16 * Math.ceil(mBytesProcessed / 16) - mBytesProcessed;

        var lenA = numberTo8Bytes(mAdditionalBytes.length * 8),
            lenC = numberTo8Bytes(mBytesProcessed * 8);

        var p = mGHashBuffer.concat(utils.getVector(u)).concat(lenA).concat(lenC);

        return ghash(mH, p);

    }

    function blockMultiplication(blockX, blockY) {

        var z = utils.getVector(16),
            v = blockY.slice(0),
            mask,
            j, i;

        for (i = 0; i < 128; i++) {

            mask = -getBit(blockX, i) & 0xff;

            // z = z xor v if bit === 1
            for (j = 0; j < 16; j++) {
                z[j] = z[j] ^ v[j] & mask;
            }

            mask = -(v[15] & 1) & 0xff;

            shiftRight(v);

            // if v[15] & 1: v = v xor [0xe1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            v[0] ^= 0xe1 & mask;
        }

        return z;
    }

    function shiftRight(dataBytes) {

        for (var i = dataBytes.length - 1; i > 0; i--) {
            dataBytes[i] = (dataBytes[i - 1] & 1) << 7 | dataBytes[i] >>> 1;
        }
        dataBytes[0] = dataBytes[0] >>> 1;

        return dataBytes;
    }

    function getBit(byteArray, bitNumber) {
        var byteIndex = Math.floor(bitNumber / 8);
        return byteArray[byteIndex] >> 7 - bitNumber % 8 & 1;
    }

    function inc(dataBytes) {

        var carry = 256;
        for (var i = 1; i <= 4; i++) {
            carry = (carry >>> 8) + dataBytes[dataBytes.length - i];
            dataBytes[dataBytes.length - i] = carry & 255;
        }

        return dataBytes;
    }

    function gctr(icb, dataBytes) {

        var blockCount = Math.ceil(dataBytes.length / 16),
            dataBlock,
            result = [];

        // We copy icb the first time gctr is called
        if (mGctrCb !== icb) {
            mGctrCb = icb.slice();
        }

        for (var block = 0; block < blockCount; block++) {

            dataBlock = dataBytes.slice(block * 16, block * 16 + 16);

            // The block cipher alters the input array, so we pass a copy.
            var e = blockCipher.encrypt(mGctrCb.slice());

            result = result.concat(utils.xorVectors(dataBlock, e));

            mGctrCb = inc(mGctrCb);
        }

        return result;
    }

    function numberTo8Bytes(integer) {
        return [
            0, 0, 0, 0,
            integer >>> 24 & 255,
            integer >>> 16 & 255,
            integer >>> 8 & 255,
            integer & 255
        ];
    }

    function padBlocks(dataBytes) {
        var padLen = 16 * Math.ceil(mAdditionalBytes.length / 16) - mAdditionalBytes.length;
        return dataBytes.concat(utils.getVector(padLen));
    }

    function clearState() {
        mBytesProcessed = 0;
        mBuffer = [];
        mCipherText = [];
        mGHashState = utils.getVector(16);
        mGHashBuffer = [];
        mGctrCb = mIvBytes = mAdditionalBytes = null;
    }

    function init(ivBytes, additionalBytes, tagLength) {

        mAdditionalBytes = additionalBytes || [];

        mTagLength = isNaN(tagLength) ? 128 : tagLength;
        if (mTagLength % 8 !== 0) {
            throw new Error("DataError");
        }

        mIvBytes = ivBytes;

        if (mIvBytes.length === 12) {
            mJ0 = mIvBytes.concat([0, 0, 0, 1]);

        } else {
            var l = 16 * Math.ceil(mIvBytes.length / 16) - mIvBytes.length;

            mJ0 = ghash(mH,
                mIvBytes
                    .concat(utils.getVector(l + 8))
                    .concat(numberTo8Bytes(mIvBytes.length * 8)));

            // Reset the ghash state so we don't affect the encrypt/decrypt ghash
            mGHashState = utils.getVector(16);
        }

        mJ0inc = inc(mJ0.slice());

        ghash(mH, padBlocks(mAdditionalBytes));
    }

    function encrypt(plainBytes) {

        mBytesProcessed = plainBytes.length;

        var c = gctr(mJ0inc, plainBytes);

        ghash(mH, c);

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        clearState();

        return c.slice().concat(t);
    }

    function decrypt(cipherBytes, tagBytes) {

        mBytesProcessed = cipherBytes.length;

        var p = gctr(mJ0inc, cipherBytes);

        ghash(mH, cipherBytes);

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        clearState();

        if (utils.arraysEqual(t, tagBytes)) {
            return p;
        } else {
            return null;
        }
    }

    function processEncrypt(plainBytes) {

        // Append incoming bytes to the end of the existing buffered bytes
        mBuffer = mBuffer.concat(plainBytes);

        // Get a run of full blocks
        var fullBlocks = mBuffer.slice(0, Math.floor(mBuffer.length / 16) * 16);

        // Keep track of the total plain bytes processed
        mBytesProcessed += fullBlocks.length;

        // Set the buffer to the remaining bytes
        mBuffer = mBuffer.slice(fullBlocks.length);

        // Process the full block with gctr. gctr maintains it's own state
        var c = gctr(mGctrCb || mJ0inc, fullBlocks);

        mCipherText = mCipherText.concat(c);

        // Process the returned blocks from gcrt
        ghash(mH, c);
    }

    function processDecrypt(cipherBytes) {

        // Append incoming bytes to the end of the existing buffered bytes
        mBuffer = mBuffer.concat(cipherBytes);

        // Get a run of full blocks.
        // We leave enough data on the end so we don't process the tag.
        var fullBlocks = mBuffer.slice(0, Math.floor((mBuffer.length - mTagLength / 8) / 16) * 16);

        // Keep track of the total plain bytes processed
        mBytesProcessed += fullBlocks.length;

        // Set the buffer to the remaining bytes
        mBuffer = mBuffer.slice(fullBlocks.length);

        // Process the full block with gctr - gctr maintains it's own state
        var c = gctr(mGctrCb || mJ0inc, fullBlocks);

        mCipherText = mCipherText.concat(c);

        // Process the returned blocks from gcrt
        ghash(mH, fullBlocks);
    }

    function finishEncrypt() {

        var c = gctr(mGctrCb, mBuffer);

        mCipherText = mCipherText.concat(c);

        mBytesProcessed += mBuffer.length;

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        var result = mCipherText.slice().concat(t);

        clearState();

        return result;
    }

    function finishDecrypt() {

        var tagLength = Math.floor(mTagLength / 8);

        var tagBytes = mBuffer.slice(-tagLength);

        mBuffer = mBuffer.slice(0, mBuffer.length - tagLength);

        var c = gctr(mGctrCb, mBuffer);

        mCipherText = mCipherText.concat(c);

        mBytesProcessed += mBuffer.length;

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        var result = mCipherText.slice();

        clearState();

        if (utils.arraysEqual(t, tagBytes)) {
            return result;
        } else {
            return null;
        }
    }

    return {
        init: init,
        encrypt: encrypt,
        decrypt: decrypt,
        processEncrypt: processEncrypt,
        processDecrypt: processDecrypt,
        finishEncrypt: finishEncrypt,
        finishDecrypt: finishDecrypt
    };

};

if (typeof operations !== "undefined") {

    var gcmInstances = {};

    msrcryptoGcm.encrypt = function( /*@dynamic*/ p) {

        //OperationError : If plaintext has a length greater than 2^39 - 256 bytes.  (0x7FFFFFFF00)
        //OperationError : If the iv member of normalizedAlgorithm has a length greater than 2^64 - 1 bytes
        //                (0xFFFFFFFFF FFFFFFFFF)
        //OperationError : If the additionalData member of normalizedAlgorithm has a length greater than 2^64 - 1 bytes
        //                 (0xFFFFFFFFF FFFFFFFFF)
        //OperationError : If the tagLength member of normalizedAlgorithm is one of 32, 64, 96, 104, 112, 120 or 128
        //                 (default if not provided)

        var result,
            id = p.workerid;

        if (!gcmInstances[id]) {
            gcmInstances[id] = msrcryptoGcm(msrcryptoBlockCipher.aes(p.keyData));
            gcmInstances[id].init(p.algorithm.iv, p.algorithm.additionalData, p.algorithm.tagLength);
        }

        if (p.operationSubType === "process") {
            gcmInstances[id].processEncrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = gcmInstances[id].finishEncrypt();
            gcmInstances[id] = null;
            return result;
        }

        result = gcmInstances[id].encrypt(p.buffer);
        gcmInstances[id] = null;
        return result;
    };

    msrcryptoGcm.decrypt = function( /*@dynamic*/ p) {

        var result,
            id = p.workerid;

        if (!gcmInstances[id]) {
            gcmInstances[id] = msrcryptoGcm(msrcryptoBlockCipher.aes(p.keyData));
            gcmInstances[id].init(p.algorithm.iv, p.algorithm.additionalData, p.algorithm.tagLength);
        }

        if (p.operationSubType === "process") {
            gcmInstances[id].processDecrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = gcmInstances[id].finishDecrypt();
            gcmInstances[id] = null;
            if (result === null) { throw new Error("OperationError"); }
            return result;
        }

        var tagLength = p.algorithm.tagLength ?  Math.floor(p.algorithm.tagLength / 8) : 16;
        var cipherBytes = p.buffer.slice(0, p.buffer.length - tagLength);
        var tagBytes = p.buffer.slice(-tagLength);

        result = gcmInstances[id].decrypt(cipherBytes, tagBytes);
        gcmInstances[id] = null;

        if (result === null) { throw new Error("OperationError"); }

        return result;
    };

    msrcryptoGcm.generateKey = function( /*@dynamic*/ p) {

        if (p.algorithm.length % 8 !== 0) {
            throw new Error();
        }

        return {
            type: "keyGeneration",
            keyData: msrcryptoPseudoRandom.getBytes(Math.floor(p.algorithm.length / 8)),
            keyHandle: new CryptoKey({
                algorithm: p.algorithm,
                extractable: p.extractable,
                usages: null || p.usages,
                type: "secret"
            })
        };
    };

    msrcryptoGcm.importKey = function( /*@dynamic*/ p) {

        var keyObject,
            keyBits = p.keyData.length * 8;

        if (p.format === "jwk") {
            keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);
        } else if (p.format === "raw") {
            if (keyBits !== 128 && keyBits !== 192 && keyBits !== 256) {
                throw new Error("invalid key length (should be 128, 192, or 256 bits)");
            }
            keyObject = { k: msrcryptoUtilities.toArray(p.keyData) };
        } else {
            throw new Error("unsupported import format");
        }

        return {
            type: "keyImport",
            keyData: keyObject.k,
            keyHandle: new CryptoKey({
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                usages: null || p.usages,
                type: "secret"
            })
        };
    };

    msrcryptoGcm.exportKey = function( /*@dynamic*/ p) {

        if (p.format === "jwk") {
            return { type: "keyExport", keyHandle: msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData) };
        }

        if (p.format === "raw") {
            return { type: "keyExport", keyHandle: p.keyData };
        }

        throw new Error("unsupported export format");
    };

    operations.register("importKey", "AES-GCM", msrcryptoGcm.importKey);
    operations.register("exportKey", "AES-GCM", msrcryptoGcm.exportKey);
    operations.register("generateKey", "AES-GCM", msrcryptoGcm.generateKey);
    operations.register("encrypt", "AES-GCM", msrcryptoGcm.encrypt);
    operations.register("decrypt", "AES-GCM", msrcryptoGcm.decrypt);
}
