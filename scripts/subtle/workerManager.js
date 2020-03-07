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

// Manages the pool of webworkers and job queue.
// We first try to find an idle webworker and pass it a crypto job.
// If there are no workers or they are all busy, we'll create a new one.
// If we're at our (somewhat arbitrary) limit for workers we'll queue the
//   job until a worker is free.
// When a worker finishes and the queue is empty it will kill itself to
//   free resources.
// However, we will keep a couple idle workers alive for future use.
// In the case webworkers are not supported <IE10 we will run in synchronous
//   mode. Jobs will be executed synchronously as they arrive using a single
//   syncWorker (pretend webworker that just runs synchronously in this same script).
var workerManager = (function() {

    // The max number of webworkers we'll spawn.
    var maxWorkers = 12;

    // The number of idle webworkers we'll allow to live for future use.
    var maxFreeWorkers = 2;

    // Storage for webworker.
    var workerPool = [];

    // Queue for jobs when all workers are busy.
    var jobQueue = [];

    // Each job gets an id.
    var jobId = 0;

    // Each worker gets an id.
    var workerId = 0;

    // setTimeout(fn,0) doesn't always preserve the correct order callbacks,
    // so we maintain our own queue.
    var callbackQueue = [];

    var setFunction = typeof setImmediate === "undefined" ? setTimeout : setImmediate;

    function executeNextCallback() {
        callbackQueue.shift()();
    }

    function queueCallback(callback) {
        callbackQueue.push(callback);
        setFunction(executeNextCallback, 0);
    }

    // Web worker status
    // The users can request to use webWorkers.  They are disabled by default.
    // When requested, a new webworker will be created and sent and initial message.
    // The result should be an ok or an error.
    // 'unavailable'    : webWorkers not supported by this browser.
    // 'available       : supported but not requested.
    // 'pending'        : requested, but still awaiting status from initialpost.
    // 'ready'          : worker created and responded ok. Can use workers.
    // 'failed'         : worker returned error after initial post. Workers cannot be uses.
    var workerStatus = webWorkerSupport ? "available" : "unavailable";

    function getFreeWorker() {

        purgeWorkerType(!asyncMode);

        // Get the first non-busy worker
        for (var i = 0; i < workerPool.length; i++) {
            if (!workerPool[i].busy) {
                return workerPool[i];
            }
        }

        return null;
    }

    // Purges web worker pool. true to purge web workers. false to purge syncworkers.
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
        // Find this worker in the array.
        for (var i = 0; i < workerPool.length; i++) {
            if (workerPool[i] === worker) {
                // Kill the webworker.
                worker.terminate();
                // Remove the worker object from the pool.
                workerPool.splice(i, 1);
                return;
            }
        }
    }

    function lookupWorkerByOperation(operation) {
        // Find this worker in the array.
        for (var i = 0; i < workerPool.length; i++) {
            if (workerPool[i].operation === operation) {
                return workerPool[i];
            }
        }
        // Didn't find the worker!?
        return null;
    }

    function queueJob(operation, data) {
        jobQueue.push({ operation: operation, data: data, id: jobId++ });
    }

    function jobCompleted(worker) {

        worker.busy = false;

        // Check the queue for waiting jobs if in async mode
        if (asyncMode) {
            if (jobQueue.length > 0) {

                var job = jobQueue.shift(),
                    i;

                continueJob(job.operation, job.data);

                // if we just grabbed a process job, post all the other jobs
                // with this operation to the webworker and let it deal with them.
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

        // Use a web worker if supported
        //   else use a synchronous worker.
        var worker;

        // We should not get here while pending
        if (workerStatus === "pending") {
            throw new Error("Creating new worker while workerstatus=pending");
        }

        if (workerStatus === "ready") {
            try {
                worker = new Worker(scriptUrl);
                worker.postMessage({ prngSeed: msrcryptoPseudoRandom.getBytes(48) });
                worker.isWebWorker = true;
            } catch (ex) {
                asyncMode = false;
                workerStatus = "failed";
                worker.terminate();
                // default to syncworker
                worker = syncWorker();
                worker.isWebWorker = false;
            }

        } else {
            worker = syncWorker();
            worker.isWebWorker = false;
        }

        // Store the operation object as a property on the worker
        //   so we can know which operation this worker is working for.
        worker.operation = operation;

        worker.id = workerId++;

        worker.busy = false;

        // The worker will call this function when it completes its job.
        worker.onmessage = function(/*@type(typeEvent)*/ e) {

            // onmessage will return initialized==true when the worker is first created.
            // we don't need to do any work yet.
            if (e.data.initialized === true) {
                return;
            }

            var op = worker.operation;

            // populate target for sync worker compatibility
            // tslint:disable-next-line: no-unused-expression
            e.target || (e.target = { data: worker.data });

            // Check if there are queued jobs for this operation
            for (var i = 0; i < jobQueue.length; i++) {
                if (jobQueue[i].operation === worker.operation) {
                    var job = jobQueue[i];
                    jobQueue.splice(i, 1);
                    postMessageToWorker(worker, job.data);
                    return;
                }
            }

            // If this is not a process operation, complete the job.
            if (!(e.data.hasOwnProperty("type") && e.data.type === "process")) {
                jobCompleted(worker);
            }

            // Send the results to the operation object and it will fire
            //   its onCompleted event.
            op.dispatchEvent(e);
        };

        // If an error occurs within the worker.
        worker.onerror = function(e) {

            var op = worker.operation;

            jobCompleted(worker);

            // Send the error to the operation object and it will fire
            //   it's onError event.
            op.dispatchEvent(e);
        };

        // Add this new worker to the worker pool.
        addWorkerToPool(worker);

        return worker;
    }

    function useWebWorkers(enable) {
        // Turns webworker on/off if supported by the browser
        // and webworker initialization succeeds. Bundling can lead to
        // webworker initialization failure if the bundle contains
        // unsupported webworker types/objects (such as DOM calls)

        if (workerStatus === "unavailable") {
            utils.consoleLog("web workers not available in this browser.");
            return;
        }

        // If webworkers already 'ready', do nothing
        if (enable === true && workerStatus === "ready") {
            return;
        }

        // If webworkers are off 'available' and we want them off, do nothing.
        if (enable === false && workerStatus === "available") {
            return;
        }

        // Turn workers off
        // There's no reason to do this for ordinary use since they are off by default,
        // but it's useful for testing.
        if (enable === false && workerStatus === "ready") {
            asyncMode = false;
            workerStatus = "available";
            utils.consoleLog("web workers disabled.");
            return;
        }

        // How did this happen?
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

        worker.postMessage({ prngSeed: msrcryptoPseudoRandom.getBytes(48) });

        return;
    }

    function abortJob(cryptoOperationObject) {
        var worker = lookupWorkerByOperation(cryptoOperationObject);
        if (worker) {
            removeWorkerFromPool(worker);
        }
    }

    // Creates or reuses a worker and starts it up on work.
    function runJob(operation, data) {

        var worker = null;

        // Status will be 'pending' when we enable webworkers and are waiting for initialization
        // to succeed/fail before proceeding. We queue the job until the worker is ready.
        if (workerStatus === "pending") {
            queueJob(operation, data);
            return;
        }

        // Get the first idle worker.
        worker = getFreeWorker();

        // Queue this job if all workers are busy and we're at our max instances
        if (asyncMode && worker === null && workerPool.length >= maxWorkers) {
            queueJob(operation, data);
            return;
        }

        // No idle workers, we'll have to create a new one.
        if (worker === null) {
            worker = createNewWorker(operation);
        }

        if (worker === null) {
            queueJob(operation, data);
            throw new Error("could not create new worker");
        }

        // Store the operation object as a property on the worker
        //   so we can know which operation this worker is working for.
        worker.operation = operation;

        // Mark this worker as 'busy'. It's about to run a job.
        worker.busy = true;

        // Assign the id of this worker to the data so we can lookup this worker
        // later to continue a process job.
        data.workerid = worker.id;

        // Start the worker
        postMessageToWorker(worker, data);
    }

    function continueJob(operation, data) {

        // Lookup the worker that is handling this operation
        var worker = lookupWorkerByOperation(operation);

        if (worker) {
            postMessageToWorker(worker, data);
            return;
        }

        // If we didn't find a worker, this is probably the first
        //  'process' message so we need to start a new worker.
        runJob(operation, data);
    }
    function postMessageToWorker(worker, data) {
        // Start the worker now if using webWorkers
        //   else, defer running until later.

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
