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

    // Create a new promise
    promise = new Promise(
        function(resolve, reject) {
            resolveFunc = resolve;
            rejectFunc = reject;
        });
    // Called when the worker returns a result
    function opDispatchEvent( /*@type(Event)*/ e) {
        // We have 4 possible result scenarios

        // 1. Error - call the onError callback
        if (e.type === "error") {
            // If the onerror callback has been set, call it.
            if (rejectFunc) {
                rejectFunc.apply(promise, [e]);
            }
            return;
        }

        // 2. Process w/ result
        //    used when streaming encryption. we get a partial result back.
        if (e.data.type === "process") {
            processResults(e.data.result, true);
            return;
        }

        // 3. Finish
        //    the last step of streaming. it will always have a result.
        if (e.data.type === "finish") {
            processResults(e.data.result, true);
            return;
        }

        // 4. Full Operation
        //    a full crypto operation. it will always have a result.
        //    Resolve the operation promise with the result
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

        // Could be the result of an import, export, generate.
        // Get the keyData and keyHandle out.
        switch (result.type) {

            // KeyImport: save the new key
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

                // KeyExport: return the export data
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

    // If the browser supports typed-arrays, return an ArrayBuffer like IE11.
    if (typedArraySupport && dataArray.pop) {

        // We can't write to an ArrayBuffer directly so we create a Uint8Array
        //   and return it's buffer property.
        return (new Uint8Array(dataArray)).buffer;
    }

    // Do nothing and just return the passed-in array.
    return dataArray;
}

function cryptoOperation(cryptoContext) {

    function processResult(result, isProcessCall) {

        // If the browser supports typed-arrays, return an ArrayBuffer like IE11.
        // result may be null when a Process() call returns for a crypto operation
        // that does not support intermediate values (i.e. sha-256 can be called
        // using streaming, but will not return intermediate results with process.)
        result = result && toArrayBufferIfSupported(result);

        if (isProcessCall) {
            promiseQueue.resolve(result);
            return;
        }

        // A normal array will be returned.
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
