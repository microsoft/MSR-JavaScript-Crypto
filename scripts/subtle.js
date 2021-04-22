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
var msrcryptoSubtle;

var utils = msrcryptoUtilities;

msrcryptoSubtle = (function() {
    function syncWorker() {
        var result;

        function postMessage(data) {

            try {
                data.workerid = this.id;
                result = msrcryptoWorker.jsCryptoRunner({
                    data: data
                });
            } catch (ex) {
                this.onerror({
                    data: ex,
                    type: "error"
                });
                return;
            }

            this.onmessage({
                data: result
            });
        }

        return {
            postMessage: postMessage,
            onmessage: null,
            onerror: null,
            terminate: function() {}
        };
    }

    var streamObject = function(op) {

        return {
            process: function(buffer) {
                return op.process(buffer);
            },
            finish: function() {
                return op.finish();
            },
            abort: function() {
                return op.abort();
            }
        };
    };

    function baseOperation(processResults) {

        var result = null,
            oncompleteCallback = null,
            onerrorCallback = null,
            retObj,
            promise,
            resolveFunc,
            rejectFunc;

        promise = new Promise(
            function(resolve, reject) {
                resolveFunc = resolve;
                rejectFunc = reject;
            });

        function opDispatchEvent(e) {
            if (e.type === "error") {
                if (rejectFunc) {
                    rejectFunc.apply(promise, [e]);
                }
                return;
            }

            if (e.data.type === "process") {
                processResults(e.data.result, true);
                return;
            }

            if (e.data.type === "finish") {
                processResults(e.data.result, true);
                return;
            }

            this.result = processResults(e.data);
            resolveFunc.apply(promise, [this.result]);

            return;
        }

        retObj = {
            dispatchEvent: opDispatchEvent,
            promise: promise,
            result: null
        };

        return retObj;
    }

    function keyOperation() {

        function processResult(result) {

            var publicKey,
                privateKey;

            switch (result.type) {

                case "keyGeneration":
                case "keyImport":
                case "keyDerive":
                    if (result.keyPair) {
                        keys.add(result.keyPair.publicKey.keyHandle, result.keyPair.publicKey.keyData);
                        keys.add(result.keyPair.privateKey.keyHandle, result.keyPair.privateKey.keyData);
                        return {
                            publicKey: result.keyPair.publicKey.keyHandle,
                            privateKey: result.keyPair.privateKey.keyHandle
                        };
                    } else {
                        keys.add(result.keyHandle, result.keyData);
                        return result.keyHandle;
                    }

                    case "keyExport":
                        return result.keyHandle;

                    case "keyPairGeneration":
                        privateKey = result.keyPair.privateKey;
                        publicKey = result.keyPair.publicKey;
                        keys.add(publicKey.keyHandle, publicKey.keyData);
                        keys.add(privateKey.keyHandle, privateKey.keyData);
                        return {
                            publicKey: publicKey.keyHandle,
                                privateKey: privateKey.keyHandle
                        };

                    default:
                        throw new Error("Unknown key operation");
            }
        }

        return baseOperation(processResult);
    }

    function toArrayBufferIfSupported(dataArray) {

        if (typedArraySupport && dataArray.pop) {

            return (new Uint8Array(dataArray)).buffer;
        }

        return dataArray;
    }

    function cryptoOperation(cryptoContext) {

        function processResult(result, isProcessCall) {

            result = result && toArrayBufferIfSupported(result);

            if (isProcessCall) {
                promiseQueue.resolve(result);
                return;
            }

            return result;
        }

        var promiseQueue = [],
            op = baseOperation(processResult);

        op.stream = cryptoContext.algorithm.stream;

        promiseQueue.add = function(label) {

            var resolveFunc,
                rejectFunc,
                promise = new Promise(
                    function(resolve, reject) {
                        resolveFunc = resolve;
                        rejectFunc = reject;
                    });

            promise.label = label;

            promiseQueue.push({
                resolve: resolveFunc,
                reject: rejectFunc,
                promise: promise
            });

            return promise;
        };

        promiseQueue.resolve = function(result) {
            var queueItem = promiseQueue.shift();
            queueItem.resolve.apply(queueItem.promise, [result]);
        };

        op.process = function(buffer) {
            cryptoContext.operationSubType = "process";
            cryptoContext.buffer = utils.toArray(buffer);
            workerManager.continueJob(this,
                utils.clone(cryptoContext));

            return promiseQueue.add("process");
        };

        op.finish = function() {
            cryptoContext.operationSubType = "finish";
            cryptoContext.buffer = [];
            workerManager.continueJob(this,
                utils.clone(cryptoContext));

            return promiseQueue.add("finish");
        };

        op.abort = function() {
            workerManager.abortJob(this);
        };
        op.algorithm = cryptoContext.algorithm || null;
        op.key = cryptoContext.keyHandle || null;

        return op;
    }

    var keys = [];

    keys.add = function(keyHandle, keyData) {
        keys.push({
            keyHandle: keyHandle,
            keyData: keyData
        });
    };

    keys.remove = function(keyHandle) {
        for (var i = 0; i < keys.length; i += 1) {
            if (keys[i].keyHandle === keyHandle) {
                keys = keys.splice(i, 1);
                return;
            }
        }
    };

    keys.lookup = function(keyHandle) {
        for (var i = 0; i < keys.length; i += 1) {
            if (keys[i].keyHandle === keyHandle) {
                return keys[i].keyData;
            }
        }
        return null;
    };

    var workerManager = (function() {

        var maxWorkers = 12;

        var maxFreeWorkers = 2;

        var workerPool = [];

        var jobQueue = [];

        var jobId = 0;

        var workerId = 0;

        var callbackQueue = [];

        var setFunction = typeof setImmediate === "undefined" ? setTimeout : setImmediate;

        function executeNextCallback() {
            callbackQueue.shift()();
        }

        function queueCallback(callback) {
            callbackQueue.push(callback);
            setFunction(executeNextCallback, 0);
        }

        var workerStatus = webWorkerSupport ? "available" : "unavailable";

        function getFreeWorker() {

            purgeWorkerType(!asyncMode);

            for (var i = 0; i < workerPool.length; i++) {
                if (!workerPool[i].busy) {
                    return workerPool[i];
                }
            }

            return null;
        }

        function purgeWorkerType(webWorker) {
            for (var i = workerPool.length - 1; i >= 0; i -= 1) {
                if (workerPool[i].isWebWorker === webWorker) {
                    workerPool[i].terminate();
                    workerPool.splice(i, 1);
                }
            }
        }

        function freeWorkerCount() {
            var freeWorkers = 0;
            for (var i = 0; i < workerPool.length; i++) {
                if (!workerPool[i].busy) {
                    freeWorkers += 1;
                }
            }
            return freeWorkers;
        }

        function addWorkerToPool(worker) {
            workerPool.push(worker);
        }

        function removeWorkerFromPool(worker) {
            for (var i = 0; i < workerPool.length; i++) {
                if (workerPool[i] === worker) {
                    worker.terminate();
                    workerPool.splice(i, 1);
                    return;
                }
            }
        }

        function lookupWorkerByOperation(operation) {
            for (var i = 0; i < workerPool.length; i++) {
                if (workerPool[i].operation === operation) {
                    return workerPool[i];
                }
            }
            return null;
        }

        function queueJob(operation, data) {
            jobQueue.push({
                operation: operation,
                data: data,
                id: jobId++
            });
        }

        function jobCompleted(worker) {

            worker.busy = false;

            if (asyncMode) {
                if (jobQueue.length > 0) {

                    var job = jobQueue.shift(),
                        i;

                    continueJob(job.operation, job.data);

                    if (job.data.operationSubType === "process") {
                        for (i = 0; i < jobQueue.length; i++) {
                            if (job.operation === jobQueue[i].operation) {
                                continueJob(jobQueue[i].operation, jobQueue[i].data);
                            }
                        }
                        for (i = jobQueue.length - 1; i >= 0; i--) {
                            if (job.operation === jobQueue[i].operation) {
                                jobQueue.splice(i, 1);
                            }
                        }
                    }
                } else if (freeWorkerCount() > maxFreeWorkers) {
                    removeWorkerFromPool(worker);
                }
            }

        }

        function createNewWorker(operation) {

            var worker;

            if (workerStatus === "pending") {
                throw new Error("Creating new worker while workerstatus=pending");
            }

            if (workerStatus === "ready") {
                try {
                    worker = new Worker(scriptUrl);
                    worker.postMessage({
                        prngSeed: msrcryptoPseudoRandom.getBytes(48)
                    });
                    worker.isWebWorker = true;
                } catch (ex) {
                    asyncMode = false;
                    workerStatus = "failed";
                    worker.terminate();
                    worker = syncWorker();
                    worker.isWebWorker = false;
                }

            } else {
                worker = syncWorker();
                worker.isWebWorker = false;
            }

            worker.operation = operation;

            worker.id = workerId++;

            worker.busy = false;

            worker.onmessage = function(e) {

                if (e.data.initialized === true) {
                    return;
                }

                var op = worker.operation;

                e.target || (e.target = {
                    data: worker.data
                });

                for (var i = 0; i < jobQueue.length; i++) {
                    if (jobQueue[i].operation === worker.operation) {
                        var job = jobQueue[i];
                        jobQueue.splice(i, 1);
                        postMessageToWorker(worker, job.data);
                        return;
                    }
                }

                if (!(e.data.hasOwnProperty("type") && e.data.type === "process")) {
                    jobCompleted(worker);
                }

                op.dispatchEvent(e);
            };

            worker.onerror = function(e) {

                var op = worker.operation;

                jobCompleted(worker);

                op.dispatchEvent(e);
            };

            addWorkerToPool(worker);

            return worker;
        }

        function useWebWorkers(enable) {
            if (workerStatus === "unavailable") {
                utils.consoleLog("web workers not available in this browser.");
                return;
            }

            if (enable === true && workerStatus === "ready") {
                return;
            }

            if (enable === false && workerStatus === "available") {
                return;
            }

            if (enable === false && workerStatus === "ready") {
                asyncMode = false;
                workerStatus = "available";
                utils.consoleLog("web workers disabled.");
                return;
            }

            if (workerStatus === "pending") {
                return;
            }

            workerStatus = "pending";

            var worker = new Worker(scriptUrl);

            function setWorkerStatus(e) {
                var succeeded = !!(e.data && e.data.initialized === true);
                worker.removeEventListener("message", setWorkerStatus, false);
                worker.removeEventListener("error", setWorkerStatus, false);
                worker.terminate();
                workerStatus = succeeded ? "ready" : "failed";
                asyncMode = succeeded;
                utils.consoleLog("web worker initialization " + (succeeded ? "succeeded. Now using web workers." :
                    "failed. running synchronously." + (e.message || "")));
                if (jobQueue.length > 0) {
                    var job = jobQueue.shift();
                    runJob(job.operation, job.data);
                }
                return;
            }

            worker.addEventListener("message", setWorkerStatus, false);
            worker.addEventListener("error", setWorkerStatus, false);

            worker.postMessage({
                prngSeed: msrcryptoPseudoRandom.getBytes(48)
            });

            return;
        }

        function abortJob(cryptoOperationObject) {
            var worker = lookupWorkerByOperation(cryptoOperationObject);
            if (worker) {
                removeWorkerFromPool(worker);
            }
        }

        function runJob(operation, data) {

            var worker = null;

            if (workerStatus === "pending") {
                queueJob(operation, data);
                return;
            }

            worker = getFreeWorker();

            if (asyncMode && worker === null && workerPool.length >= maxWorkers) {
                queueJob(operation, data);
                return;
            }

            if (worker === null) {
                worker = createNewWorker(operation);
            }

            if (worker === null) {
                queueJob(operation, data);
                throw new Error("could not create new worker");
            }

            worker.operation = operation;

            worker.busy = true;

            data.workerid = worker.id;

            postMessageToWorker(worker, data);
        }

        function continueJob(operation, data) {

            var worker = lookupWorkerByOperation(operation);

            if (worker) {
                postMessageToWorker(worker, data);
                return;
            }

            runJob(operation, data);
        }

        function postMessageToWorker(worker, data) {
            data.workerid = worker.id;

            if (asyncMode) {

                worker.postMessage(data);

            } else {

                var func = (function(postData) {
                    return function() {
                        return worker.postMessage(postData);
                    };
                })(data);

                queueCallback(func);
            }

            return;
        }

        return {
            runJob: runJob,
            continueJob: continueJob,
            abortJob: abortJob,
            useWebWorkers: useWebWorkers
        };

    })();

    function checkOperation(operationType, algorithmName) {
        if (!operations.exists(operationType, algorithmName)) {
            throw new Error("unsupported algorithm");
        }
    }

    var subtleParameters = [{
            name: "algorithm",
            type: "Object",
            required: true
        },
        {
            name: "keyHandle",
            type: "Object",
            required: true
        },
        {
            name: "buffer",
            type: "Array",
            required: false
        },
        {
            name: "signature",
            type: "Array",
            required: true
        },
        {
            name: "format",
            type: "String",
            required: true
        },
        {
            name: "keyData",
            type: "Object",
            required: true
        },
        {
            name: "extractable",
            type: "Boolean",
            required: false
        },
        {
            name: "usages",
            type: "Array",
            required: false
        },
        {
            name: "derivedKeyType",
            type: "Object",
            required: true
        },
        {
            name: "length",
            type: "Number",
            required: false
        },
        {
            name: "extractable",
            type: "Boolean",
            required: true
        },
        {
            name: "usages",
            type: "Array",
            required: true
        },
        {
            name: "keyData",
            type: "Array",
            required: true
        }
    ];

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

    function lookupKeyData(handle) {
        var data = keys.lookup(handle);

        if (!data) {
            throw new Error("key not found");
        }

        return data;
    }

    function buildParameterCollection(operationName, parameterSet) {

        var parameterCollection = {
                operationType: operationName
            },
            operationParameterSet,
            expectedParam,
            actualParam,
            i;

        if (operationName === "importKey" && (parameterSet[0] === "raw" || parameterSet[0] === "spki")) {
            operationName = "importKeyRaw";
        }

        if (operationName === "importKey" && parameterSet[0] === "jwk") {
            operationName = "importKeyJwk";
        }

        operationParameterSet = subtleParametersSets[operationName];

        for (i = 0; i < operationParameterSet.length; i += 1) {

            expectedParam = subtleParameters[operationParameterSet[i]];
            actualParam = parameterSet[i];

            if (actualParam == null) {
                if (expectedParam.required) {
                    throw new Error(expectedParam.name);
                } else {
                    continue;
                }
            }

            if (actualParam.subarray) {
                actualParam = utils.toArray(actualParam);
            }

            if (utils.getObjectType(actualParam) === "ArrayBuffer") {
                actualParam = utils.toArray(actualParam);
            }

            if (msrcryptoUtilities.getObjectType(actualParam) !== expectedParam.type) {
                throw new Error(expectedParam.name);
            }

            if (expectedParam.name === "algorithm") {

                actualParam.name = actualParam.name.toUpperCase();

                if (actualParam.iv) {
                    actualParam.iv = utils.toArray(actualParam.iv);
                }

                if (actualParam.publicExponent) {
                    actualParam.publicExponent = utils.toArray(actualParam.publicExponent);
                }

                if (actualParam.salt) {
                    actualParam.salt = utils.toArray(actualParam.salt);
                }

                if (actualParam.additionalData) {
                    actualParam.additionalData = utils.toArray(actualParam.additionalData);
                }

                if (actualParam.hash && !actualParam.hash.name && utils.getObjectType(actualParam.hash) === "String") {
                    actualParam.hash = {
                        name: actualParam.hash
                    };
                }
            }

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

        checkOperation(operationName, pc.algorithm.name);

        if (pc.keyHandle) {
            pc.keyData = lookupKeyData(pc.keyHandle);
        }

        if (pc.keyHandle1) {
            pc.keyData1 = lookupKeyData(pc.keyHandle1);
        }

        if (pc.algorithm && pc.algorithm.public) {
            pc.additionalKeyData = lookupKeyData(pc.algorithm.public);
        }

        var op = keyFunc ? keyOperation(pc) : cryptoOperation(pc);

        if (keyFunc || pc.buffer || operationName === "deriveBits" || operationName === "wrapKey") {
            workerManager.runJob(op, pc);
        }

        if (op.stream) {
            return Promise.resolve(streamObject(op));
        }

        return op.promise;
    }
    var publicMethods = {

        encrypt: function(algorithm, keyHandle, buffer) {
            return executeOperation("encrypt", arguments, 0);
        },

        decrypt: function(algorithm, keyHandle, buffer) {
            return executeOperation("decrypt", arguments, 0);
        },

        sign: function(algorithm, keyHandle, buffer) {
            return executeOperation("sign", arguments, 0);
        },

        verify: function(algorithm, keyHandle, signature, buffer) {
            return executeOperation("verify", arguments, 0);
        },

        digest: function(algorithm, buffer) {
            return executeOperation("digest", arguments, 0);
        },

        generateKey: function(algorithm, extractable, keyUsage) {
            return executeOperation("generateKey", arguments, 1);
        },

        deriveKey: function(algorithm, baseKey, derivedKeyType, extractable, keyUsage) {
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
                        keyLength = derivedKeyType.length || {
                            "SHA-1": 512,
                            "SHA-224": 512,
                            "SHA-256": 512,
                            "SHA-384": 1024,
                            "SHA-512": 1024
                        } [derivedKeyType.hash.name.toUpperCase()];
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
                    })["catch"](function(err) {
                        reject(err);
                    });

            });

        },

        deriveBits: function(algorithm, baseKey, length) {
            return executeOperation("deriveBits", arguments, 0);
        },

        importKey: function(format, keyData, algorithm, extractable, keyUsage) {
            return executeOperation("importKey", arguments, 1);
        },

        exportKey: function(format, keyHandle) {
            return executeOperation("exportKey", [keyHandle.algorithm, format, keyHandle], 1);
        },

        wrapKey: function(format, key, wrappingKey, wrappingKeyAlgorithm) {
            var encrypt = this.encrypt,
                exportKey = this.exportKey;

            return new Promise(function(resolve, reject) {

                if (key.extractable === false ||
                    key.usages.indexOf("wrapKey") < 0 ||
                    wrappingKey.algorithm.name.toUpperCase() !== wrappingKeyAlgorithm.name) {
                    reject(new Error("InvalidAccessError"));
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

                ["catch"](function(err) {
                    reject(err);
                });
            });
        },

        unwrapKey: function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
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

                ["catch"](function(err) {
                    reject(err);
                });
            });

        }

    };

    var internalMethods = {
        useWebWorkers: workerManager.useWebWorkers
    };

    return {
        publicMethods: publicMethods,
        internalMethods: internalMethods
    };

})();