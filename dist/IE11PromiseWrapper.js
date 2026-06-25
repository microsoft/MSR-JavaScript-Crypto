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
// IE11 has a W3C WebCrypto API that uses events and not promises.
// When using msrCrypto you want to use the native WebCrypto, when available, and
// msrCrypto when it's not. The API calls for the msrCrypto and native WebCrypto are
// the same. So your code will work for both. However, it won't work with IE11
// because it uses events instead of Promises.
// This script wraps the native IE11 WebCryto calls
// AMD/global wrapper
(function(root, factory) {

    if (typeof define === "function" && define.amd) {
        define([], function() {
            return root.crypto = factory(root);
        });
    } else {
        root.crypto = factory(root);
    }

}(this, function(global) {

    // Check for IE11 native crypto implementation.
    // IE11 uses window.msCrypto. Later versions of IE use window.crypto
    if (typeof global.msCrypto !== "undefined" && typeof global.Promise !== "undefined") {

        var ie11Subtle = msCrypto.subtle,
            crypto,
            isUnsupportedHash = function(algorithm) {
                // doesn't have a hash - could be ok in some cases
                if (!algorithm.hasOwnProperty("hash")) { return false; }

                // hash requires a name
                if (!algorithm.hash.hasOwnProperty("name")) { return true; }

                if (["SHA-256", "SHA-384"].indexOf(algorithm.hash.name) < 0) { return true; }

                return false;
            },
            wrapPromise = function(operation, fixFunc) {

                var promise = new Promise(function(resolve, reject) {

                    operation.oncomplete = function(resultEvent) {

                        var result = resultEvent.target.result;

                        if (fixFunc) { result = fixFunc(result); }

                        resolve(result);
                    };

                    operation.onerror = function(resultEvent) {
                        reject("error : " + JSON.stringify(operation));
                    };

                });

                return promise;
            };

        crypto = function() {

            var keyHashStore = [];

            return {

                subtle: {

                    encrypt: function(algorithm, keyHandle, buffer) {

                        // IE11 AES-GCM returns { ciphertext, tag}
                        // while it should return [ciphertext|tag] as a single array

                        var fixFunc,
                            bufferLen = buffer.pop ? buffer.length : buffer.byteLength;

                        if (bufferLen === 0) {
                            return Promise.reject({ message: "IE11 Encrypt does not allow empty buffer" });
                        }

                        if (algorithm.name.toUpperCase() === "AES-GCM") {

                            if (algorithm.iv.length !== 12) {
                                return Promise.reject({ message: "IE11 AES-GCM IV length must be 12-bytes" });
                            }

                            fixFunc = function(result) {
                                var c = new Uint8Array(result.ciphertext),
                                    t = new Uint8Array(result.tag),
                                    newArray = new Uint8Array(c.length + t.length),
                                    i;

                                for (i = 0; i < c.length; i += 1) {
                                    newArray[i] = c[i];
                                    newArray[c.length + i] = t[i];
                                }

                                return newArray.buffer;
                            };
                        }

                        if (buffer.pop) { buffer = new Uint8Array(buffer); }

                        return wrapPromise(ie11Subtle.encrypt(algorithm, keyHandle, buffer), fixFunc);
                    },

                    decrypt: function(algorithm, keyHandle, buffer) {
                        if (algorithm.name.toUpperCase() === "AES-GCM") {

                            // break buffer into { ciphertext, tag }
                            // tslint:disable-next-line: no-bitwise
                            var tagLen = algorithm.tagLength >>> 3,
                                ct = (buffer.buffer || buffer).slice(0, buffer.byteLength - tagLen),
                                tag = (buffer.buffer || buffer).slice(buffer.byteLength - tagLen);

                            buffer = ct;
                            algorithm.tag = tag;
                        }

                        return wrapPromise(ie11Subtle.decrypt(algorithm, keyHandle, buffer));
                    },

                    sign: function(algorithm, keyHandle, buffer) {

                        var alName = algorithm.name.toUpperCase(),
                            i;

                        // IE11 RSASSA-PKCS1-v1_5/HMAC  requires hash property in algorithm,
                        // but it is not required by W3C
                        if ((alName === "RSASSA-PKCS1-V1_5" || alName === "HMAC") &&
                            !algorithm.hasOwnProperty("hash")) {

                            // look up the hash associated with this key
                            for (i = 0; i < keyHashStore.length; i += 1) {
                                if (keyHashStore[i].key === keyHandle) {
                                    algorithm.hash = keyHashStore[i].hash;
                                    break;
                                }
                            }

                            if (!algorithm.hasOwnProperty("hash")) {
                                return Promise.reject("algorithm requires hash property");
                            }

                        }
                        return wrapPromise(ie11Subtle.sign(algorithm, keyHandle, buffer));
                    },

                    verify: function(algorithm, keyHandle, signature, buffer) {

                        var alName = algorithm.name.toUpperCase(),
                            i;

                        // IE11 RSASSA-PKCS1-v1_5/HMAC requires hash property in algorithm,
                        // but it is not required by W3C
                        if ((alName === "RSASSA-PKCS1-V1_5" || alName === "HMAC") &&
                            !algorithm.hasOwnProperty("hash")) {

                            // look up the hash associated with this key
                            for (i = 0; i < keyHashStore.length; i += 1) {
                                if (keyHashStore[i].key === keyHandle) {
                                    algorithm.hash = keyHashStore[i].hash;
                                    break;
                                }
                            }

                            if (!algorithm.hasOwnProperty("hash")) {
                                return Promise.reject("algorithm requires hash property");
                            }

                        }
                        return wrapPromise(ie11Subtle.verify(algorithm, keyHandle, signature, buffer));
                    },

                    digest: function(algorithm, buffer) {

                        var op;

                        if ((buffer.length || buffer.byteLength) === 0) {
                            return Promise.reject({ message: "IE11 Digest does not allow empty buffer" });
                        }

                        // If hash alg is unsupported IE11 throws when called and does not result in a rejected promise.
                        // So we catch the throw and reject.
                        try {
                            op = ie11Subtle.digest(algorithm, buffer);
                        } catch (e) {
                            return Promise.reject(e);
                        }

                        return wrapPromise(op);

                    },

                    generateKey: function(algorithm, extractable, keyUsage) {
                        var fixFunction;

                        // IE11 does not include the hash property on the key(s)
                        if (algorithm.name.toUpperCase() === "RSASSA-PKCS1-V1_5") {

                            if (!algorithm.hasOwnProperty("hash")) {
                                return Promise.reject("hash: Missing or not an AlgorithmIdentifier");
                            }
                            fixFunction = function(result) {

                                // We cannot attach a new 'hash' property to key.algorithm
                                // so we'll store the hash and look it up when needed.
                                keyHashStore.push({ key: result.privateKey, hash: algorithm.hash });
                                keyHashStore.push({ key: result.publicKey, hash: algorithm.hash });

                                return result;
                            };
                        }

                        return wrapPromise(ie11Subtle.generateKey(algorithm, extractable, keyUsage), fixFunction);
                    },

                    deriveKey: function(algorithm, baseKey, derivedKeyType, extractable, keyUsage) {
                        return wrapPromise(ie11Subtle.deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsage));
                    },

                    deriveBits: function(algorithm, baseKey, length) {
                        return Promise.reject("deriveBits() not supported on IE11");
                    },

                    importKey: function(format, keyData, algorithm, extractable, keyUsage) {

                        var fixFunction,
                            keyDataArray,
                            alName = algorithm.name.toUpperCase(),
                            op;

                        if (format === "jwk") {
                            if (keyData.hasOwnProperty("ext")) {
                                keyData.extractable = keyData.ext;
                                delete keyData.ext;
                            }

                            // IE11 wants keyData as an a Uint8Array of ASCII
                            keyDataArray = new Uint8Array(JSON.stringify(keyData).split("").map(function(c) { return c.charCodeAt(0); }));

                            // Change IE11 "extractable" property to "ext"
                            if (keyData.hasOwnProperty("extractable")) {
                                keyData.ext = keyData.extractable;
                                delete keyData.extractable;
                            }
                        }

                        if (format === "raw") {
                            keyDataArray = keyData;
                        }

                        // IE11 does not include the hash property on the key(s)
                        if (alName === "RSASSA-PKCS1-V1_5" || alName === "HMAC") {

                            if (!algorithm.hasOwnProperty("hash")) {
                                return Promise.reject("hash: Missing or not an AlgorithmIdentifier");
                            }

                            if (!algorithm.hash.hasOwnProperty("name") || ["SHA-256", "SHA-384"].indexOf(algorithm.hash.name) < 0) {
                                return Promise.reject({ message: "RsaHashedImportParams: hash: Algorithm: Unrecognized name" });
                            }

                            fixFunction = function(key) {

                                // We cannot attach a new 'hash' property to key.algorithm
                                // so we'll store the hash and look it up when needed.
                                keyHashStore.push({ key: key, hash: algorithm.hash });

                                return key;
                            };
                        }

                        try {
                            op = ie11Subtle.importKey(format, keyDataArray, algorithm, extractable, keyUsage);
                        } catch (e) {
                            return Promise.reject(e);
                        }

                        return wrapPromise(op, fixFunction);
                    },

                    exportKey: function(format, keyHandle) {

                        // IE11 will return a byte encoded ArrayBuffer of a stringified key.
                        // Change this to an object
                        var fixFunc,
                            alg;

                        if (format === "jwk") {
                            fixFunc = function(result) {

                                var keyObj = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(result)));

                                if (keyObj.hasOwnProperty("extractable")) {
                                    keyObj.ext = keyObj.extractable;
                                    delete keyObj.extractable;
                                }

                                alg = keyHandle.algorithm;

                                if (alg.name.substring(0, 2).toUpperCase() === "AE") {
                                    keyObj.alg = "A" + alg.length + alg.name.substring(alg.name.length - 3).toUpperCase();
                                }

                                return keyObj;
                            };
                        }

                        return wrapPromise(ie11Subtle.exportKey(format, keyHandle), fixFunc);
                    },

                    wrapKey: function(format, key, wrappingKey, wrappingKeyAlgorithm) {
                        return wrapPromise(ie11Subtle.wrapKey(format, key, wrappingKey, wrappingKeyAlgorithm));
                    },

                    unwrapKey: function(wrappedKey, keyAlgorithm, keyEncryptionKey, extractable, keyUsage) {
                        return wrapPromise(ie11Subtle.unwrapKey(wrappedKey, keyAlgorithm, keyEncryptionKey, extractable, keyUsage));
                    }

                }
            };
        };

        return crypto();

    } else {
        return global.crypto;
    }

}));
