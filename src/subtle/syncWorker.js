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

// This worker is used when webworkers aren't available.
// It will function synchronously but use the same
//   mechanisms that the asynchronous webworkers use.
function syncWorker() {
    var result;

    // PostMessage is how you interact with a worker. You post some data to the worker
    // and it will process it and return it's data to the onmessage function.
    // Since we're really running synchronously, we call the crypto function in
    // PostMessage and wait for the result. Then we call the OnMessage function with
    // that result. This will give the same behavior as a web-worker.
    function postMessage(data) {

        // Web-workers will automatically return an error message when an
        // error is thrown within the web worker.
        // When using a sync worker, we'll have to catch thrown errors, so we
        // need a try/catch block here.
        try {
            // add the workerid to the parameters. when streaming multiple crypto operations that
            // call the same functions (i.e. sha-256 & hmac-256) we need a way to
            // maintain separate instances. we use the worker id for this.
            data.workerid = this.id;
            result = msrcryptoWorker.jsCryptoRunner({ data: data });
        } catch (ex) {
            this.onerror({ data: ex, type: "error" });
            return;
        }

        this.onmessage({ data: result });
    }

    return {
        postMessage: postMessage,
        onmessage: null,
        onerror: null,
        terminate: function() {
            // This is a no-op to be compatible with webworker.
        }
    };
}
