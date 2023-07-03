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
        throw new Error("unsupported algorithm");
    }
}

var isNativeCryptoKeyAvailable = typeof CryptoKey !== "undefined";

// The list of possible parameters passed to the subtle interface.
var subtleParameters = [
   /* 0 */ { name: "algorithm", type: "Object", required: true },
   /* 1 */ { name: "keyHandle", type: isNativeCryptoKeyAvailable ? "CryptoKey" : "Object", required: true },
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
    deriveBits: [0, 1, 9],
    wrapKey: [1, 1, 0],
    unwrapKey: [2, 0, 1, 6, 7]
};

// Looks up the stored key data for a given keyHandle
function lookupKeyData(handle) {
    var data = keys.lookup(handle);

    if (!data) {
        throw new Error("key not found");
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
                throw new Error(expectedParam.name);
            } else {
                continue;
            }
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
            throw new Error(expectedParam.name);
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
    if (keyFunc || pc.buffer || operationName === "deriveBits" || operationName === "wrapKey") {
        workerManager.runJob(op, pc);
    }

    if (op.stream) {
        // This is streaming operation. A streamObject will be returned to the promise now.
        return Promise.resolve(streamObject(op));
    }

    return op.promise;
}
var publicMethods = {

    encrypt: function(algorithm, keyHandle, buffer) {
        /// <signature>
        /// <summary>Encrypt a UInt8Array of data. Encrypt will return an ArrayBuffer if supported,
        ///     otherwise it will return a regular Array.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="ArrayBuffer" />
        /// </signature>
        /// <signature>
        /// <summary>Encrypt an array of bytes. Encrypt will return an ArrayBuffer if supported,
        ///     otherwise it will return a regular Array.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes (number from 0-255)</param>
        ///     <returns type="Array" />
        /// </signature>
        /// <signature>
        /// <summary>Encrypt an array of bytes. Encrypt will return an ArrayBuffer if supported,
        ///     otherwise it will return a regular Array.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="Array" optional="true">an array of bytes (number from 0-255)</param>
        ///     <returns type="ArrayBuffer" />
        /// </signature>

        return executeOperation("encrypt", arguments, 0);
    },

    decrypt: function(algorithm, keyHandle, buffer) {
        /// <signature>
        ///     <summary>Decrypt a UInt8Array of data.
        ///     Decrypt will return an ArrayBuffer if supported, otherwise it will return an Array of byte
        ///         values(numbers from 0 - 255)</summary >
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Decrypt an array of byte values. Decrypt will return an ArrayBuffer if supported,
        ///         otherwise it will return a regular Array.</summary >
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>

        return executeOperation("decrypt", arguments, 0);
    },

    sign: function(algorithm, keyHandle, buffer) {
        /// <signature>
        ///     <summary>Sign a UInt8Array of data.
        ///     Sign will return a signature as an ArrayBuffer if supported,
        ///     otherwise it will return an Array of byte values (numbers from 0-255)</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Sign an array of byte values. Sign will return an ArrayBuffer if supported,
        ///     otherwise it will return a regular Array.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>

        return executeOperation("sign", arguments, 0);
    },

    verify: function(algorithm, keyHandle, signature, buffer) {
        /// <signature>
        ///     <summary>Verify a signature.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="signature" type="UInt8Array">UInt8Array</param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Verify a signature.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="signature" type="UInt8Array">UInt8Array</param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Verify a signature.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="signature" type="Array">An array of bytes values (numbers from 0-255)</param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Verify a signature.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="signature" type="Array">An array of bytes values (numbers from 0-255)</param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>

        return executeOperation("verify", arguments, 0);
    },

    digest: function(algorithm, buffer) {
        /// <signature>
        ///     <summary>Digest data using a specified cryptographic hash algorithm</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Digest data using a specified cryptographic hash algorithm</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        return executeOperation("digest", arguments, 0);
    },

    generateKey: function(algorithm, extractable, keyUsage) {
        /// <signature>
        ///     <summary>Generate a new key for use with the algorithm specified by the algorithm parameter</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="extractable" type="Boolean" optional="true"></param>
        ///     <param name="keyUsage" type="Array" optional="true"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>

        return executeOperation("generateKey", arguments, 1);
    },

    deriveKey: function(algorithm, baseKey, derivedKeyType, extractable, keyUsage) {
        /// <signature>
        ///     <summary>Generate a key for the specified derivedKeyType, using the specified cryptographic
        ///         key derivation algorithm with the given baseKey as input.</summary >
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="baseKey" type="Key"></param>
        ///     <param name="deriveKeyType" type="Algorithm"></param>
        ///     <param name="extractable" type="Boolean" optional="true"></param>
        ///     <param name="keyUsage" type="Array" optional="true"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>

        var deriveBits = this.deriveBits,
            importKey = this.importKey;

        return new Promise(function(resolve, reject) {

            var keyLength;

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
        /// <signature>
        ///     <summary>Generate an array of bytes from a given baseKey as input.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="baseKey" type="Key"></param>
        ///     <param name="length" type="Number">Number of bits to return.</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>

        return executeOperation("deriveBits", arguments, 0);
    },

    importKey: function(format, keyData, algorithm, extractable, keyUsage) {
        /// <signature>
        ///     <summary>Constructs a new Key object using the key data specified by the keyData parameter.</summary>
        ///     <param name="format" type="String"></param>
        ///     <param name="keyData" type="Object">An object representing a key in jwk format.</param>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="extractable" type="Boolean" optional="true"></param>
        ///     <param name="keyUsage" type="Array" optional="true"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>
        return executeOperation("importKey", arguments, 1);
    },

    exportKey: function(format, keyHandle) {
        /// <signature>
        ///     <summary>Exports the given key material of the Key object as specified by the key parameter.</summary>
        ///     <param name="format" type="String"></param>
        ///     <param name="key" type="Key"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>

        // Export is one of the few calls where the caller does not supply an algorithm
        // since it's already a property of the key to be exported.
        // So, we're pulling it out of the key and adding it to the parameter set since
        // it is used as a switch to route the parameters to the right function.
        // Now we don't have to treat this as a special case in the underlying code.
        return executeOperation("exportKey", [keyHandle.algorithm, format, keyHandle], 1);
    },

    wrapKey: function(format, key, wrappingKey, wrappingKeyAlgorithm) {
        /// <signature>
        ///     <summary>Returns a KeyOperation object which will asynchronously return an array containing the
        ///         key material of key, encrypted with keyEncryptionKey using the specified
        ///         keyWrappingAlgorithm.</summary >
        ///     <param name="format" type="String"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="wrappingKey" type="Key"></param>
        ///     <param name="wrappingKeyAlgorithm" type="Algorithm"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>

        var encrypt = this.encrypt,
            exportKey = this.exportKey;

        return new Promise(function(resolve, reject) {

            if (key.extractable === false ||
                wrappingKey.usages.indexOf("wrapKey") < 0 ||
                wrappingKey.algorithm.name.toUpperCase() !== wrappingKeyAlgorithm.name) {
                reject(new Error("InvalidAccessError"));
                return;
            }

            exportKey(format, key)

                .then(function(keyData) {

                    console.log(utils.toBase64(keyData));

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
        /// <signature>
        ///     <summary>Construct a Key object from encrypted key material.</summary>
        ///     <param name="format" type="String"></param>
        ///     <param name="unwrappingKey" type="Array">An array of bytes values (numbers from 0-255)</param>
        ///     <param name="unwrapAlgorithm" type="Algorithm"></param>
        ///     <param name="keyEncryptionKey" type="Key"></param>
        ///     <param name="extractable" unwrappedKeyAlgorithm type="Boolean" optional="true"></param>
        ///     <param name="keyUsage" type="Array" optional="true"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Construct a Key object from encrypted key material.</summary>
        ///     <param name="format" type="String"></param>
        ///     <param name="unwrappingKey" type="UInt8Array"></param>
        ///     <param name="unwrapAlgorithm" type="Algorithm"></param>
        ///     <param name="unwrappedKeyAlgorithm" type="Key"></param>
        ///     <param name="extractable" type="Boolean" optional="true"></param>
        ///     <param name="keyUsage" type="Array" optional="true"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>

        var decrypt = this.decrypt,
            importKey = this.importKey;

        return new Promise(function(resolve, reject) {

            if (unwrappingKey.usages.indexOf("unwrapKey") < 0 ||
                unwrappingKey.algorithm.name.toUpperCase() !== unwrapAlgorithm.name) {
                reject(new Error("InvalidAccessError"));
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
