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

/* @constructor */ function MsrcryptoPrng() {
    /// <summary>Pseudo Random Number Generator function/class.</summary>
    /// <remarks>This is the PRNG engine, not the entropy collector.
    /// The engine must be initialized with adequate entropy in order to generate cryptographically secure
    /// random numbers. It is hard to get entropy, but see the entropy function/class for the entropy gatherer.
    /// This is not an object instantiation, but the definition of the object. The actual
    /// object must be instantiated somewhere else as needed.
    /// </remarks>

    if (!(this instanceof MsrcryptoPrng)) {
        throw new Error("create MsrcryptoPrng object with new keyword");
    }

    // Fall-back for browsers which do not implements crypto API yet
    // implementation of http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf.
    // Use AES-256 in CTR mode of operation as defined in Section 10.2.1.
    var initialized = false;

    // Internal state definitions are as follows.
    // v : internal variable that will ultimately be the random output
    // key: the AES key (256 bits)
    // keyLen: the AES key length in bytes
    // reseedCounter: the number of requests for pseudo-random bits since instantiation/reseeding
    // reseedInterval: Maximum number of generate calls per seed or reseed. SP800-90A says 2^48 for AES.
    var key;
    var v;
    var keyLen;
    var seedLen;
    var reseedCounter = 1;
    var reseedInterval = Math.pow(2, 48);

    // Initialize this instance (constructor like function)
    initialize();

    function addOne(counter) {
        /// <summary>Adds one to a big integer represented in an array (the first argument).</summary>
        /// <param name="counter" counter="Array">The counter byte array to add one to encoded in big endian;
        /// index 0 is the MSW.</param >
        var i;
        for (i = counter.length - 1; i >= 0; i -= 1) {
            counter[i] += 1;
            if (counter[i] >= 256) {
                counter[i] = 0;
            }
            if (counter[i]) {
                break;
            }
        }
    }

    function initialize() {
        /// <summary>Instantiate the PRNG with given entropy and personalization string.</summary>
        /// <param name="entropy" type="Array">Array of bytes obtained from the source of entropy input.</param>
        /// <param name="personalizationString" type="Array">Optional application-provided
        /// personalization string.</param >
        key = msrcryptoUtilities.getVector(32);
        v = msrcryptoUtilities.getVector(16);            // AES block length
        keyLen = 32;
        seedLen = 48;       // From SP800-90A, section 10.2.1 as of 2014.
        reseedCounter = 1;
    }

    function reseed(entropy, /*@optional*/ additionalEntropy) {
        /// <summary>Reseed the PRNG with additional entropy.</summary>
        /// <param name="entropy" type="Array">Input entropy.</param>
        /// <param name="additionalEntropy" type="Array">Optional additional entropy input.</param>
        additionalEntropy = additionalEntropy || [0];
        if (additionalEntropy.length > seedLen) {
            throw new Error("Incorrect entropy or additionalEntropy length");
        }
        additionalEntropy = additionalEntropy.concat(msrcryptoUtilities.getVector(seedLen - additionalEntropy.length));

        // Process the entropy input in blocks with the same additional entropy.
        // This is equivalent to the caller chunking entropy in blocks and calling this function for each chunk.
        entropy = entropy.concat(msrcryptoUtilities.getVector((seedLen - (entropy.length % seedLen)) % seedLen));
        for (var i = 0; i < entropy.length; i += seedLen) {
            var seedMaterial = msrcryptoUtilities.xorVectors(entropy.slice(i, i + seedLen), additionalEntropy);
            update(seedMaterial);
        }
        reseedCounter = 1;
    }

    function update(providedData) {
        /// <summary>Add the providedData to the internal entropy pool, and update internal state.</summary>
        /// <param name="providedData" type="Array">Input to add to the internal entropy pool.</param>
        var temp = [];
        var blockCipher = new msrcryptoBlockCipher.aes(key);
        while (temp.length < seedLen) {
            addOne(v);
            var toEncrypt = v.slice(0, 16);
            var outputBlock = blockCipher.encrypt(toEncrypt); // AES-256
            temp = temp.concat(outputBlock);
        }
        temp = msrcryptoUtilities.xorVectors(temp, providedData);
        key = temp.slice(0, keyLen);
        v = temp.slice(keyLen);
    }

    function generate(requestedBytes, /*@optional*/ additionalInput) {
        /// <summary>Generate pseudo-random bits, and update the internal PRNG state.</summary>
        /// <param name="requestedBytes" type="Number">Number of pseudo-random bytes to be returned.</param>
        /// <param name="additionalInput" type="Array">Application-provided additional input array (optional).</param>
        /// <returns>Generated pseudo-random bytes.</returns>
        if (requestedBytes >= 65536) {
            throw new Error("too much random requested");
        }
        if (reseedCounter > reseedInterval) {
            throw new Error("Reseeding is required");
        }
        if (additionalInput && additionalInput.length > 0) {
            while (additionalInput.length < seedLen) {
                additionalInput = additionalInput.concat(
                    msrcryptoUtilities.getVector(seedLen - additionalInput.length));
            }
            update(additionalInput);
        } else {
            additionalInput = msrcryptoUtilities.getVector(seedLen);
        }
        var temp = [];
        var blockCipher = new msrcryptoBlockCipher.aes(key);
        while (temp.length < requestedBytes) {
            addOne(v);
            var toEncrypt = v.slice(0, v.length);
            var outputBlock = blockCipher.encrypt(toEncrypt);
            temp = temp.concat(outputBlock);
        }
        temp = temp.slice(0, requestedBytes);
        update(additionalInput);
        reseedCounter += 1;
        return temp;
    }

    return {
        reseed: reseed,
        /// <summary>Reseed the PRNG with additional entropy.</summary>
        /// <param name="entropy" type="Array">Input entropy.</param>
        /// <param name="additionalEntropy" type="Array">Optional additional entropy input.</param>

        getBytes: function(length, /*@optional*/ additionalInput) {
            if (!initialized) {
                throw new Error("can't get randomness before initialization");
            }
            return generate(length, /*@optional*/ additionalInput);
        },
        getNonZeroBytes: function(length, additionalInput) {
            if (!initialized) {
                throw new Error("can't get randomness before initialization");
            }
            var result = [];
            var buff;
            while (result.length < length) {
                buff = generate(length, additionalInput);
                for (var i = 0; i < buff.length; i += 1) {
                    if (buff[i] !== 0) {
                        result.push(buff[i]);
                    }
                }
            }
            return result.slice(0, length);
        },
        init: function(entropy, /*@optional*/ personalization) {
            /// <summary>Initialize the PRNG by seeing with entropy and optional input data.</summary>
            /// <param name="entropy" type="Array">Input entropy.</param>
            /// <param name="personalization" type="Array">Optional input.</param>
            if (entropy.length < seedLen) {
                throw new Error("Initial entropy length too short");
            }
            initialize();
            reseed(entropy, personalization);
            initialized = true;
        }
    };
}

// This is the PRNG object per instantiation, including one per worker.
// The instance in the main thread is used to seed the instances in workers.
// TODO: Consider combining the entropy pool in the main thread with the PRNG instance in the main thread.
/// <disable>JS3085.VariableDeclaredMultipleTimes</disable>
                   var msrcryptoPseudoRandom = new MsrcryptoPrng();
/// <enable>JS3085.VariableDeclaredMultipleTimes</enable>
