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

var msrcryptoWorker = (function() {

    // If we're running in a webworker we need to postMessage to return our result
    //   otherwise just return the value as normal.
    function returnResult(result) {

        if (workerInitialized && runningInWorkerInstance) {
            self.postMessage(result);
        }
        return result;
    }

    var workerId,
        operationType,
        operationSubType;

    return {

        jsCryptoRunner: function(e) {

            workerId = e.data.workerid;
            operationType = e.data.operationType;
            operationSubType = e.data.operationSubType;

            var operation = e.data.operationType,
                result,
                func = operations[operation][e.data.algorithm.name],
                p = e.data;

            if (!operations.exists(operation, e.data.algorithm.name)) {
                throw new Error("unregistered algorithm.");
            }

            if (p.operationSubType) {
                result = returnResult({ type: p.operationSubType, result: func(p) });
            } else {
                result = returnResult(func(p));
            }

            return result;
        },

        returnResult: returnResult
    };

})();

// If this is running in a webworker we need self.onmessage to receive messages from
//   the calling script.
// If we are in 'synchronous mode' (everything running in one script)
//   we don't want to override self.onmessage.
// We could be running in a webworker as a main script (not a child script)
//   so we will ignore messages if we've not been initialized.
if (runningInWorkerInstance) {

    self.onmessage = function(/*@type(typeEvent)*/e) {

        // When this worker first gets instantiated we will receive seed data
        //   for this workers prng.
        if (!workerInitialized && e.data.prngSeed) {
            var entropy = e.data.prngSeed;
            msrcryptoPseudoRandom.init(entropy);
            workerInitialized = true;
            return msrcryptoWorker.returnResult({ initialized: true });
        }

        // Process the crypto operation
        if (workerInitialized === true) { msrcryptoWorker.jsCryptoRunner(e); }

    };
}
