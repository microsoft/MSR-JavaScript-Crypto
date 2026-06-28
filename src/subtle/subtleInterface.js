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

function checkOperation(operationType, algorithmName) {
    if (!operations.exists(operationType, algorithmName)) {
        throw utils.error("NotSupportedError", "Unrecognized or unsupported algorithm.");
    }
}

// The list of possible parameters passed to the subtle interface.
var subtleParameters = [
   /* 0 */ { name: "algorithm", type: "Object", required: true },
   /* 1 */ { name: "keyHandle", type: "Object", required: true },
   /* 2 */ { name: "buffer", type: "Array", required: false },
   /* 3 */ { name: "signature", type: "Array", required: true },
   /* 4 */ { name: "format", type: "String", required: true },
   /* 5 */ { name: "keyData", type: "Object", required: true },
   /* 6 */ { name: "extractable", type: "Boolean", required: false },
   /* 7 */ { name: "usages", type: "Array", required: false },
   /* 8 */ { name: "derivedKeyType", type: "Object", required: true },
   /* 9 */ { name: "length", type: "Number", required: false },
   /* 10 */ { name: "extractable", type: "Boolean", required: true },
   /* 11 */ { name: "usages", type: "Array", required: true },
   /* 12 */ { name: "keyData", type: "Array", required: true }
];

// The set of expected parameters passed to each subtle function.
var subtleParametersSets = {
    encrypt: [0, 1, 2],
    decrypt: [0, 1, 2],
    sign: [0, 1, 2],
    verify: [0, 1, 3, 2],
    digest: [0, 2],
    generateKey: [0, 6, 7],
    importKeyRaw: [4, 12, 0, 10, 11],
    importKeyJwk: [4, 5, 0, 10, 11],
    exportKey: [0, 4, 1, 6, 7],
    deriveKey: [0, 1, 8, 6, 7],
    deriveBits: [0, 1, 9]
};

// Looks up the stored key data for a given keyHandle
function lookupKeyData(handle) {
    var data = keys.lookup(handle);

    if (!data) {
        throw utils.error("InvalidAccessError", "key not found");
    }

    return data;
}

// This function processes each parameter passed by the user. Each parameter
// is compared against an expected parameter. It should be of the expected type.
// Typed-Array parameters are converted to regular Arrays.
function buildParameterCollection(operationName, parameterSet) {

    var parameterCollection = { operationType: operationName },
        operationParameterSet,
        expectedParam,
        actualParam,
        i;

    if (operationName === "importKey" && (parameterSet[0] === "raw" || parameterSet[0] === "spki" || parameterSet[0] === "pkcs8")) {
        operationName = "importKeyRaw";
    }

    if (operationName === "importKey" && parameterSet[0] === "jwk") {
        operationName = "importKeyJwk";
    }

    operationParameterSet = subtleParametersSets[operationName];

    for (i = 0; i < operationParameterSet.length; i += 1) {

        expectedParam = subtleParameters[operationParameterSet[i]];
        actualParam = parameterSet[i];

        // Verify the required parameters are present.
        if (actualParam == null) {
            if (expectedParam.required) {
                throw new TypeError("Missing required parameter: " + expectedParam.name);
            } else {
                continue;
            }
        }

        // A string algorithm identifier (e.g. "SHA-256") is shorthand for
        // { name: "SHA-256" }, per the W3C AlgorithmIdentifier (object or
        // DOMString). Normalize it to an object before the type check below.
        if (expectedParam.name === "algorithm" && utils.getObjectType(actualParam) === "String") {
            actualParam = { name: actualParam };
        }

        // If this parameter is a typed-array convert it to a regular array.
        if (actualParam.subarray) {
            actualParam = utils.toArray(actualParam);
        }

        // If this parameter is an ArrayBuffer convert it to a regular array.
        if (utils.getObjectType(actualParam) === "ArrayBuffer") {
            actualParam = utils.toArray(actualParam);
        }

        // Verify the actual parameter is of the expected type.
        if (msrcryptoUtilities.getObjectType(actualParam) !== expectedParam.type) {
            throw new TypeError("Invalid type for parameter: " + expectedParam.name);
        }

        // If this parameter is an algorithm object convert it's name to upperCase.
        if (expectedParam.name === "algorithm") {

            actualParam.name = actualParam.name.toUpperCase();

            // If the algorithm has a typed-array IV, convert it to a regular array.
            if (actualParam.iv) {
                actualParam.iv = utils.toArray(actualParam.iv);
            }

            // If the algorithm has a typed-array publicExponent, convert it to a regular array.
            if (actualParam.publicExponent) {
                actualParam.publicExponent = utils.toArray(actualParam.publicExponent);
            }

            // If the algorithm has a typed-array Salt, convert it to a regular array.
            if (actualParam.salt) {
                actualParam.salt = utils.toArray(actualParam.salt);
            }

            // If the algorithm has a typed-array AdditionalData, convert it to a regular array.
            if (actualParam.additionalData) {
                actualParam.additionalData = utils.toArray(actualParam.additionalData);
            }

            // If this algorithm has a hash property in the form 'hash: hashName'
            // Convert it to hash: {name: hashName} as per the W3C spec.
            if (actualParam.hash && !actualParam.hash.name && utils.getObjectType(actualParam.hash) === "String") {
                actualParam.hash = { name: actualParam.hash };
            }
        }

        // KeyWrap has two keyHandle parameters. We add '1' to the second param name
        // to avoid a duplicate name.
        if (parameterCollection.hasOwnProperty(expectedParam.name)) {
            parameterCollection[expectedParam.name + "1"] = actualParam;
        } else {
            parameterCollection[expectedParam.name] = actualParam;
        }
    }

    return parameterCollection;
}

function executeOperation(operationName, parameterSet, keyFunc) {

    // WebCrypto SubtleCrypto methods never throw synchronously; any error
    // (bad parameters, unsupported algorithm, etc.) must be surfaced as a
    // rejected promise. Wrap the synchronous setup so we honor that contract.
    try {

        var pc = buildParameterCollection(operationName, parameterSet);

        // Verify this type of operation is supported by this library (encrypt, digest, etc...)
        checkOperation(operationName, pc.algorithm.name);

        // Add the key data to the parameter object
        if (pc.keyHandle) {
            pc.keyData = lookupKeyData(pc.keyHandle);
        }

        // Add the key data to the parameter object
        // KeyWrap has two keyHandle parameters - this handles the second key.
        if (pc.keyHandle1) {
            pc.keyData1 = lookupKeyData(pc.keyHandle1);
        }

        // ECDH.DeriveBits passes a public key in the algorithm
        if (pc.algorithm && pc.algorithm.public) {
            pc.additionalKeyData = lookupKeyData(pc.algorithm.public);
        }

        var op = keyFunc ? keyOperation(pc) : cryptoOperation(pc);

        // Run the crypto now if a buffer is supplied
        //   else wait until process() and finish() are called.
        if (keyFunc || pc.buffer || operationName === "deriveBits") {
            workerManager.runJob(op, pc);
        }

        if (op.stream) {
            // This is streaming operation. A streamObject will be returned to the promise now.
            return Promise.resolve(streamObject(op));
        }

        return op.promise;

    } catch (error) {
        return Promise.reject(error);
    }
}
var publicMethods = {

    encrypt: function(algorithm, cryptoKey, buffer) {
        /**
         * Encrypt data. Returns an ArrayBuffer if supported, otherwise a regular Array.
         * @param {Algorithm} algorithm - The encryption algorithm and its parameters.
         * @param {CryptoKey} cryptoKey - The key to encrypt with.
         * @param {Uint8Array|Array} [buffer] - The data to encrypt (a Uint8Array or an array of byte values 0-255).
         * @returns {Promise<ArrayBuffer|Array>} The encrypted data.
         */

        return executeOperation("encrypt", arguments, 0);
    },

    decrypt: function(algorithm, cryptoKey, buffer) {
        /**
         * Decrypt data. Returns an ArrayBuffer if supported, otherwise an array of byte values (0-255).
         * @param {Algorithm} algorithm - The decryption algorithm and its parameters.
         * @param {CryptoKey} cryptoKey - The key to decrypt with.
         * @param {Uint8Array|Array} [buffer] - The data to decrypt (a Uint8Array or an array of byte values 0-255).
         * @returns {Promise<ArrayBuffer|Array>} The decrypted data.
         */

        return executeOperation("decrypt", arguments, 0);
    },

    sign: function(algorithm, cryptoKey, buffer) {
        /**
         * Sign data. Returns a signature as an ArrayBuffer if supported, otherwise an array of byte values (0-255).
         * @param {Algorithm} algorithm - The signature algorithm and its parameters.
         * @param {CryptoKey} cryptoKey - The key to sign with.
         * @param {Uint8Array|Array} [buffer] - The data to sign (a Uint8Array or an array of byte values 0-255).
         * @returns {Promise<ArrayBuffer|Array>} The signature.
         */

        return executeOperation("sign", arguments, 0);
    },

    verify: function(algorithm, cryptoKey, signature, buffer) {
        /**
         * Verify a signature.
         * @param {Algorithm} algorithm - The signature algorithm and its parameters.
         * @param {CryptoKey} cryptoKey - The key to verify with.
         * @param {Uint8Array|Array} signature - The signature to verify (a Uint8Array or an array of byte values 0-255).
         * @param {Uint8Array|Array} [buffer] - The data that was signed (a Uint8Array or an array of byte values 0-255).
         * @returns {Promise<boolean>} True if the signature is valid.
         */

        return executeOperation("verify", arguments, 0);
    },

    digest: function(algorithm, buffer) {
        /**
         * Digest data using a specified cryptographic hash algorithm.
         * @param {Algorithm} algorithm - The hash algorithm.
         * @param {Uint8Array|Array} [buffer] - The data to hash (a Uint8Array or an array of byte values 0-255).
         * @returns {Promise<ArrayBuffer|Array>} The computed digest.
         */
        return executeOperation("digest", arguments, 0);
    },

    generateKey: function(algorithm, extractable, keyUsage) {
        /**
         * Generate a new key for use with the algorithm specified by the algorithm parameter.
         * @param {Algorithm} algorithm - The algorithm the key will be used with.
         * @param {boolean} [extractable] - Whether the key may be exported.
         * @param {Array} [keyUsage] - The permitted key usages.
         * @returns {Promise<Key|{publicKey: Key, privateKey: Key}>} The generated key or key pair.
         */

        return executeOperation("generateKey", arguments, 1);
    },

    deriveKey: function(algorithm, baseKey, derivedKeyType, extractable, keyUsage) {
        /**
         * Generate a key for the specified derivedKeyType, using the specified cryptographic
         * key derivation algorithm with the given baseKey as input.
         * @param {Algorithm} algorithm - The key derivation algorithm and its parameters.
         * @param {Key} baseKey - The base key used to derive the new key.
         * @param {Algorithm} derivedKeyType - The algorithm the derived key will be used with.
         * @param {boolean} [extractable] - Whether the derived key may be exported.
         * @param {Array} [keyUsage] - The permitted key usages.
         * @returns {Promise<Key>} The derived key.
         */

        var deriveBits = this.deriveBits,
            importKey = this.importKey;

        return new Promise(function(resolve, reject) {

            var keyLength;

            // Accept both the string and object HashAlgorithmIdentifier forms.
            if (derivedKeyType.hash && !derivedKeyType.hash.name && utils.getObjectType(derivedKeyType.hash) === "String") {
                derivedKeyType.hash = { name: derivedKeyType.hash };
            }

            switch (derivedKeyType.name.toUpperCase()) {
                case "AES-CBC":
                case "AES-GCM":
                    keyLength = derivedKeyType.length;
                    break;
                case "HMAC":
                    keyLength = derivedKeyType.length || // HMAC length defaults to hash block size
                        { "SHA-1": 512, "SHA-224": 512, "SHA-256": 512, "SHA-384": 1024, "SHA-512": 1024 }[derivedKeyType.hash.name.toUpperCase()];
                    break;
                default:
                    reject(new Error("No Supported"));
                    return;
            }

            deriveBits(algorithm, baseKey, keyLength)
                .then(function(bits) {
                    return importKey("raw", bits, derivedKeyType, extractable, keyUsage);
                })
                .then(function(key) {
                    resolve(key);
                })
                // tslint:disable-next-line: no-string-literal
                ["catch"](function(err) {
                    reject(err);
                });

        });

    },

    deriveBits: function(algorithm, baseKey, length) {
        /**
         * Generate an array of bytes from a given baseKey as input.
         * @param {Algorithm} algorithm - The key derivation algorithm and its parameters.
         * @param {Key} baseKey - The base key used to derive the bits.
         * @param {number} length - Number of bits to return.
         * @returns {Promise<ArrayBuffer|Array>} The derived bits.
         */

        return executeOperation("deriveBits", arguments, 0);
    },

    importKey: function(format, keyData, algorithm, extractable, keyUsage) {
        /**
         * Construct a new Key object using the key data specified by the keyData parameter.
         * @param {string} format - The format of the key data (e.g. "raw", "jwk", "spki", "pkcs8").
         * @param {Object|Array} keyData - The key data (a JWK object, or key bytes for other formats).
         * @param {Algorithm} algorithm - The algorithm the key will be used with.
         * @param {boolean} [extractable] - Whether the key may be exported.
         * @param {Array} [keyUsage] - The permitted key usages.
         * @returns {Promise<Key>} The imported key.
         */
        return executeOperation("importKey", arguments, 1);
    },

    exportKey: function(format, cryptoKey) {
        /**
         * Export the key material of the Key object as specified by the format parameter.
         * @param {string} format - The format to export the key in (e.g. "raw", "jwk", "spki", "pkcs8").
         * @param {CryptoKey} cryptoKey - The key to export.
         * @returns {Promise<Object|ArrayBuffer|Array>} The exported key material.
         */

        // Export is one of the few calls where the caller does not supply an algorithm
        // since it's already a property of the key to be exported.
        // So, we're pulling it out of the key and adding it to the parameter set since
        // it is used as a switch to route the parameters to the right function.
        // Now we don't have to treat this as a special case in the underlying code.
        return executeOperation("exportKey", [cryptoKey.algorithm, format, cryptoKey], 1);
    },

    wrapKey: function(format, key, wrappingKey, wrappingKeyAlgorithm) {
        /**
         * Asynchronously return an array containing the key material of key, encrypted with
         * wrappingKey using the specified wrappingKeyAlgorithm.
         * @param {string} format - The format to export the key in before wrapping.
         * @param {Key} key - The key to wrap.
         * @param {Key} wrappingKey - The key used to encrypt (wrap) the exported key material.
         * @param {Algorithm} wrappingKeyAlgorithm - The algorithm used to wrap the key.
         * @returns {Promise<ArrayBuffer|Array>} The wrapped key.
         */

        var encrypt = this.encrypt,
            exportKey = this.exportKey;

        return new Promise(function(resolve, reject) {

            if (key.extractable === false ||
                utils.indexOf(wrappingKey.usages, "wrapKey") < 0 ||
                wrappingKey.algorithm.name.toUpperCase() !== wrappingKeyAlgorithm.name) {
                reject(utils.error("InvalidAccessError", "key cannot be wrapped with the supplied wrapping key"));
                return;
            }

            exportKey(format, key)

                .then(function(keyData) {

                    return encrypt(wrappingKeyAlgorithm, wrappingKey, format === "jwk" ?
                        utils.stringToBytes(JSON.stringify(keyData, null, 0)) : keyData);
                })

                .then(function(cipherArrayBuffer) {
                    resolve(cipherArrayBuffer);
                })

                // tslint:disable-next-line: no-string-literal
                ["catch"](function(err) {
                    reject(err);
                });
        });
    },

    unwrapKey: function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        //format, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable and keyUsages
        /**
         * Construct a Key object from encrypted key material.
         * @param {string} format - The format of the wrapped key material.
         * @param {Uint8Array|Array} wrappedKey - The encrypted key material.
         * @param {Key} unwrappingKey - The key used to decrypt (unwrap) the wrapped key.
         * @param {Algorithm} unwrapAlgorithm - The algorithm used to unwrap the key.
         * @param {Algorithm} unwrappedKeyAlgorithm - The algorithm the unwrapped key will be used with.
         * @param {boolean} [extractable] - Whether the unwrapped key may be exported.
         * @param {Array} [keyUsages] - The permitted key usages.
         * @returns {Promise<Key>} The unwrapped key.
         */

        var decrypt = this.decrypt,
            importKey = this.importKey;

        return new Promise(function(resolve, reject) {

            if (utils.indexOf(unwrappingKey.usages, "unwrapKey") < 0 ||
                unwrappingKey.algorithm.name.toUpperCase() !== unwrapAlgorithm.name) {
                reject(utils.error("InvalidAccessError", "key cannot be unwrapped with the supplied unwrapping key"));
                return;
            }

            decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey)

                .then(function(keyPlain) {
                    return importKey(format, format === "jwk" ? JSON.parse(utils.bytesToString(keyPlain)) : keyPlain,
                        unwrappedKeyAlgorithm, extractable, keyUsages);
                })

                .then(function(key) {
                    resolve(key);
                })

                // tslint:disable-next-line: no-string-literal
                ["catch"](function(err) {
                    reject(err);
                });
        });

    }

};

var internalMethods = {
    useWebWorkers: workerManager.useWebWorkers
};
