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

var msrcryptoSha = function(name, der, h, k, blockBytes, blockFunction, truncateTo) {
    /// <summary>
    /// Returns a hash function using the passed in parameters.
    /// </summary>
    /// <param name="name" type="String">Name of the hash function.</param>
    /// <param name="der" type="Array"></param>
    /// <param name="h" type="Array"></param>
    /// <param name="k" type="Array"></param>
    /// <param name="blockBytes" type="Number">The number of bytes in a block.</param>
    /// <param name="blockFunction" type="BlockFunctionTypeDef">Function for processing blocks.</param>
    /// <param name="truncateTo" type="Number">Truncate the resulting hash to a fixed length.</param>
    /// <returns type="Object"></returns>

    var utils = msrcryptoUtilities;

    // Make a copy of h so we don't alter the initialization array.
    var hv = h.slice(),
        w = new Array(blockBytes),
        buffer = [],
        blocksProcessed = 0;

    function hashBlocks(message) {
        /// <summary>
        /// Breaks a array of data into full blocks and hashes each block in sequence.
        /// Data at the end of the message that does not fill an entire block is
        /// returned.
        /// </summary>
        /// <param name="message" type="Array">Byte data to hash</param>
        /// <returns type="Array">Unprocessed data at the end of the message that did
        /// not fill an entire block.</returns>

        var blockCount = Math.floor(message.length / blockBytes);

        // Process each  block of the message
        for (var block = 0; block < blockCount; block++) {
            blockFunction(message, block, hv, k, w);
        }

        // Keep track of the number of blocks processed.
        // We have to put the total message size into the padding.
        blocksProcessed += blockCount;

        // Return the unprocessed data.
        return message.slice(blockCount * blockBytes);
    }

    function hashToBytes() {
        /// <summary>
        /// Converts stored hash values (32-bit ints) to bytes.
        /// </summary>
        /// <returns type="Array"></returns>

        // Move the results to an uint8 array.
        var hash = [];

        for (var i = 0; i < hv.length; i++) {
            hash = hash.concat(utils.int32ToBytes(hv[i]));
        }

        // Truncate the results depending on the hash algorithm used.
        hash.length = truncateTo / 8;

        return hash;
    }

    function addPadding(messageBytes) {
        /// <summary>
        /// Builds and appends padding to a message
        /// </summary>
        /// <param name="messageBytes" type="Array">Message to pad</param>
        /// <returns type="Array">The message array + padding</returns>

        var padLen = blockBytes - messageBytes.length % blockBytes;

        // If there is 8 (16 for sha-512) or less bytes of padding, pad an additional block.
        // tslint:disable-next-line: no-unused-expression
        (padLen <= (blockBytes / 8)) && (padLen += blockBytes);

        // Create a new Array that will contain the message + padding
        var padding = utils.getVector(padLen);

        // Set the 1 bit at the end of the message data
        padding[0] = 128;

        // Set the length equal to the previous data len + the new data len
        var messageLenBits = (messageBytes.length + blocksProcessed * blockBytes) * 8;

        // Set the message length in the last 8 bytes
        //padding[padLen - 4] = messageLenBits >>> 24 & 255;
        //padding[padLen - 3] = messageLenBits >>> 16 & 255;
        //padding[padLen - 2] = messageLenBits >>> 8 & 255;
        //padding[padLen - 1] = messageLenBits & 255;
        //messageLenBits = Math.floor(messageLenBits / 0x100000000);
        //padding[padLen - 8] = messageLenBits >>> 24 & 255;
        //padding[padLen - 7] = messageLenBits >>> 16 & 255;
        //padding[padLen - 6] = messageLenBits >>> 8 & 255;
        //padding[padLen - 5] = messageLenBits & 255;

        for (var i = 1; i <= 8; i++) {
            padding[padLen - i] = messageLenBits % 0x100;
            messageLenBits = Math.floor(messageLenBits / 0x100);
        }
        return messageBytes.concat(padding);
    }

    function computeHash(messageBytes) {
        /// <summary>
        /// Computes the hash of an entire message.
        /// </summary>
        /// <param name="messageBytes" type="Array">Byte array to hash</param>
        /// <returns type="Array">Hash of message bytes</returns>

        buffer = hashBlocks(messageBytes);

        return finish();
    }

    function process(messageBytes) {
        /// <summary>
        /// Call process repeatedly to hash a stream of bytes. Then call 'finish' to
        /// complete the hash and get the final result.
        /// </summary>
        /// <param name="messageBytes" type="Array"></param>

        // Append the new data to the buffer (previous unprocessed data)
        buffer = buffer.concat(messageBytes);

        // If there is at least one block of data, hash it
        if (buffer.length >= blockBytes) {

            // The remaining unprocessed data goes back into the buffer
            buffer = hashBlocks(buffer);
        }

        return;
    }

    function finish() {
        /// <summary>
        /// Called after one or more calls to process. This will finalize the hashing
        /// of the 'streamed' data and return the hash.
        /// </summary>
        /// <returns type="Array">Hash of message bytes</returns>

        // All the full blocks of data have been processed. Now we pad the rest and hash.
        // Buffer should be empty now.
        if (hashBlocks(addPadding(buffer)).length !== 0) {
            throw new Error("buffer.length !== 0");
        }

        // Convert the intermediate hash values to bytes
        var result = hashToBytes();

        // Reset the buffer
        buffer = [];

        // Restore the initial hash values
        hv = h.slice();

        // Reset the block counter
        blocksProcessed = 0;

        return result;
    }

    return {
        name: name,
        computeHash: computeHash,
        process: process,
        finish: finish,
        der: der,
        hashLen: truncateTo,
        maxMessageSize: 0xFFFFFFFF // (2^32 - 1 is max array size in JavaScript)
    };

};
