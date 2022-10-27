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

var msrcryptoPadding = msrcryptoPadding || {};

msrcryptoPadding.pkcsv7 = function(blockSize) {

    function pad(messageBlocks) {
        /// <signature>
        ///     <summary>Apply PKCS7 padding to message</summary>
        ///     <param name="messageBlocks" type="Array">An array of blocks to pad</param> <
        /// </signature>

        var lastIndex = messageBlocks.length - 1 >= 0 ? messageBlocks.length - 1 : 0;
        var lastBlock = messageBlocks[lastIndex];
        var lastBlockLength = lastBlock.length;
        var createNewBlock = lastBlockLength === blockSize;

        if (createNewBlock) {
            var newBlock = [];
            var i;
            for (i = 0; i < blockSize; i += 1) {
                newBlock.push(blockSize);
            }
            messageBlocks.push(newBlock);
        } else {
            // tslint:disable-next-line: no-bitwise
            var byteToAdd = blockSize - lastBlockLength & 0xff;
            while (lastBlock.length !== blockSize) {
                lastBlock.push(byteToAdd);
            }
        }

    }

    function unpad(messageBytes) {
        /// <signature>
        ///     <summary>Remove PKCS7 padding from the message</summary>
        ///     <param name="messageBytes" type="Array"></param>
        ///     <returns type="Boolean">True for legal padding. False if not.</returns>
        /// </signature>

        var verified = true;

        // Verify the cipher text is an increment of block length
        if (messageBytes.length % blockSize !== 0) {
            verified = false;
        }

        // Get the last block
        var lastBlock = messageBytes.slice(-blockSize);

        // Get value of the last element in the block
        // This will be the number of padding bytes on the end if the
        // message was decrypted correctly.
        var padLen = lastBlock[lastBlock.length - 1];

        for (var i = 0; i < blockSize; i++) {
            var isPaddingElement = blockSize - i <= padLen;
            var isCorrectValue = lastBlock[i] === padLen;
            verified = (isPaddingElement ? isCorrectValue : true) && verified;
        }

        var trimLen = verified ? padLen : 0;

        messageBytes.length -= trimLen;

        return verified;
    }

    return {
        pad: pad,
        unpad: unpad
    };

};

var msrcryptoCbc = function(blockCipher) {

    var blockSize = blockCipher.blockSize / 8;

    var paddingScheme = msrcryptoPadding.pkcsv7(blockSize);

    // Merges an array of block arrays into a single byte array
    var mergeBlocks = function(/*@type(Array)*/tab) {
        var res = [], i, j;
        for (i = 0; i < tab.length; i += 1) {
            var block = tab[i];
            for (j = 0; j < block.length; j += 1) {
                res.push(block[j]);
            }
        }
        return res;
    };

    // Breaks an array of bytes into an array of block size arrays of bytes
    function getBlocks(dataBytes) {

        var blocks = [];

        // Append incoming bytes to the end of the existing buffered bytes
        mBuffer = mBuffer.concat(dataBytes);

        var blockCount = Math.floor(mBuffer.length / blockSize);

        for (var i = 0; i < blockCount; i++) {
            blocks.push(mBuffer.slice(i * blockSize, (i + 1) * blockSize));
        }

        // Set the buffer to the remaining bytes
        mBuffer = mBuffer.slice(blockCount * blockSize);

        return blocks;
    }

    function encryptBlocks(blocks) {

        var result = [],
            toEncrypt;

        for (var i = 0; i < blocks.length; i++) {
            toEncrypt = msrcryptoUtilities.xorVectors(mIvBytes, blocks[i]);
            result.push(blockCipher.encrypt(toEncrypt));
            mIvBytes = result[i];
        }

        return result;
    }

    function decryptBlocks(blocks) {

        var result = [],
            toDecrypt,
            decrypted;

        for (var i = 0; i < blocks.length; i += 1) {
            toDecrypt = blocks[i].slice(0, blocks[i].length);
            decrypted = blockCipher.decrypt(toDecrypt);
            result.push(msrcryptoUtilities.xorVectors(mIvBytes, decrypted));
            mIvBytes = blocks[i];
        }

        return result;
    }

    function clearState() {
        mBuffer = [];
        mResultBuffer = [];
        mIvBytes = null;
    }

    var mBuffer = [],
        mResultBuffer = [],
        mIvBytes;

    return {

        init: function(ivBytes) {

            if (ivBytes.length !== blockSize) {
                throw new Error("Invalid iv size");
            }

            mIvBytes = ivBytes.slice();
        },

        // Does a full encryption of the input
        encrypt: function(plainBytes) {
            /// <summary>perform the encryption of the plain text message</summary>
            /// <param name="plainBytes" type="Array">the plain text to encrypt</param>
            /// <returns type="Array">the encrypted message</returns>

            var result = encryptBlocks(getBlocks(plainBytes));
            mResultBuffer = mResultBuffer.concat(mergeBlocks(result));

            return this.finishEncrypt();
        },

        // Encrypts full blocks of streamed input
        processEncrypt: function(plainBytes) {

            var result = mergeBlocks(encryptBlocks(getBlocks(plainBytes)));

            return result;
        },

        // Call when done streaming input
        finishEncrypt: function() {

            var blocks = mBuffer.length === 1 ? [[mBuffer[0]]] : [mBuffer];

            paddingScheme.pad(blocks);

            var result = mResultBuffer.concat(mergeBlocks(encryptBlocks(blocks)));

            clearState();

            return result;
        },

        // Does a full decryption and returns the result
        decrypt: function(/*@type(Array)*/cipherBytes) {
            /// <summary>perform the decryption of the encrypted message</summary>
            /// <param name="encryptedBytes" type="Array">the plain text to encrypt</param>
            /// <returns type="Array">the encrypted message</returns>

            this.processDecrypt(cipherBytes);

            return this.finishDecrypt();
        },

        // Decrypts full blocks of streamed data
        processDecrypt: function(cipherBytes) {

            var result = decryptBlocks(getBlocks(cipherBytes));

            mResultBuffer = mResultBuffer.concat(mergeBlocks(result));

            return;
        },

        // Called to finalize streamed decryption
        finishDecrypt: function() {

            var result = mResultBuffer;

            // Strip the padding.
            var verified = paddingScheme.unpad(result);

            clearState();

            return result;
        }

    };
};

if (typeof operations !== "undefined") {

    var cbcInstances = {};

    msrcryptoCbc.workerEncrypt = function(p) {

        var result,
            id = p.workerid;

        if (!cbcInstances[id]) {
            cbcInstances[id] = msrcryptoCbc(msrcryptoBlockCipher.aes(p.keyData));
            cbcInstances[id].init(p.algorithm.iv);
        }

        if (p.operationSubType === "process") {
            return cbcInstances[id].processEncrypt(p.buffer);
        }

        if (p.operationSubType === "finish") {
            result = cbcInstances[id].finishEncrypt();
            cbcInstances[id] = null;
            return result;
        }

        result = cbcInstances[id].encrypt(p.buffer);
        cbcInstances[id] = null;
        return result;
    };

    msrcryptoCbc.workerDecrypt = function(p) {

        var result,
            id = p.workerid;

        if (!cbcInstances[id]) {
            cbcInstances[id] = msrcryptoCbc(msrcryptoBlockCipher.aes(p.keyData));
            cbcInstances[id].init(p.algorithm.iv);
        }

        if (p.operationSubType === "process") {
            cbcInstances[id].processDecrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = cbcInstances[id].finishDecrypt();
            cbcInstances[id] = null;
            return result;
        }

        result = cbcInstances[id].decrypt(p.buffer);
        cbcInstances[id] = null;
        return result;
    };

    msrcryptoCbc.generateKey = function(p) {

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

    msrcryptoCbc.importKey = function(p) {

        var keyObject;
        var keyBits = p.keyData.length * 8;

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

        p.algorithm.length = keyObject.k.length * 8;

        return {
            keyData: keyObject.k,
            keyHandle: new CryptoKey({
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                usages: null || p.usages,
                type: "secret"
            }),
            type: "keyImport"
        };
    };

    msrcryptoCbc.exportKey = function(p) {

        if (p.format === "jwk") {
            return { type: "keyExport", keyHandle: msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData) };
        }

        if (p.format === "raw") {
            return { type: "keyExport", keyHandle: p.keyData };
        }

        throw new Error("unsupported export format");
    };

    operations.register("importKey", "AES-CBC", msrcryptoCbc.importKey);
    operations.register("exportKey", "AES-CBC", msrcryptoCbc.exportKey);
    operations.register("generateKey", "AES-CBC", msrcryptoCbc.generateKey);
    operations.register("encrypt", "AES-CBC", msrcryptoCbc.workerEncrypt);
    operations.register("decrypt", "AES-CBC", msrcryptoCbc.workerDecrypt);
}
