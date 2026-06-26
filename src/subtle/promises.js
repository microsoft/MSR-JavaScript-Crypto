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
// Promise polyfill wrapper.
// Exposes the constructor on msrCrypto.Promise (the native Promise when one is
// available, otherwise the bundled implementation) so the polyfill installer
// can wire it to the global scope. Also installs a global Promise directly
// when the host lacks one (for example, legacy IE).
(function(factory) {

    // Resolve the real global object across browsers, web workers, and Node.
    var globalObject = (function() {
        if (typeof globalThis !== "undefined") { return globalThis; }
        if (typeof self !== "undefined") { return self; }
        if (typeof window !== "undefined") { return window; }
        if (typeof global !== "undefined") { return global; }
        return this;
    })();

    // Prefer a native Promise; only build the bundled one when needed.
    var providedPromise = (typeof globalObject.Promise !== "undefined")
        ? globalObject.Promise
        : factory();

    // Expose the constructor on the msrCrypto export so msrcryptoPolyfill.js
    // (or any consumer) can install it on the global scope on demand.
    if (typeof module === "object" && module.exports) {
        module.exports.Promise = module.exports.Promise || providedPromise;
    } else if (globalObject.msrCrypto) {
        globalObject.msrCrypto.Promise = globalObject.msrCrypto.Promise || providedPromise;
    }

    // Install a global Promise when the host lacks one.
    if (typeof globalObject.Promise === "undefined") {
        globalObject.Promise = providedPromise;
    }

}(function() {

    var Promise = function(executor, id) {
        /// <summary>
        /// Creates a new promise.
        /// </summary>
        /// <param name="executor" type="function">A function that takes two parameters:
        ///     function(resolved, rejected) {...}</param >
        /// <returns type="Promise">A new Promise object</returns>

        if (!(this instanceof Promise)) {
            throw new Error("use 'new' keyword with Promise constructor");
        }

        // State: 0 = pending, 1 = fulfilled, 2 = rejected.
        var state = 0,
            settledValue = null,
            // Queue of handlers registered while pending. Each entry is
            // { onCompleted, onRejected, resolveNext, rejectNext } so a single
            // list keeps each handler aligned with its chained promise's
            // resolve/reject. This lets rejections propagate through then()
            // calls that omit a rejection handler so a trailing catch() still
            // receives the error. (The previous implementation tracked these in
            // separate arrays that fell out of alignment and dropped such
            // rejections, silently swallowing errors.)
            handlers = [];

        // Invoke a single registered handler against the settled value and
        // route the outcome to its chained promise. A missing handler passes
        // the value through (fulfilled -> resolveNext, rejected -> rejectNext)
        // so a later catch() still sees an earlier rejection. A throwing
        // handler rejects the chained promise.
        function runHandler(handler) {

            var callback = (state === 1) ? handler.onCompleted : handler.onRejected;

            if (!callback) {
                (state === 1 ? handler.resolveNext : handler.rejectNext)(settledValue);
                return;
            }

            var result;
            try {
                result = callback(settledValue);
            } catch (handlerError) {
                handler.rejectNext(handlerError);
                return;
            }

            handler.resolveNext(result);
        }

        // Move the promise to its final state and flush any queued handlers.
        // When fulfilled with a thenable, adopt that thenable's eventual state
        // so returning a promise from then() chains as expected.
        function settle(newState, value) {

            if (state !== 0) {
                return;
            }

            if (newState === 1 && value && (typeof value === "object" || typeof value === "function")) {

                var thenFunction;
                try {
                    thenFunction = value.then;
                } catch (accessError) {
                    settle(2, accessError);
                    return;
                }

                if (typeof thenFunction === "function") {
                    var handled = false;
                    try {
                        thenFunction.call(
                            value,
                            function(result) { if (!handled) { handled = true; settle(1, result); } },
                            function(reason) { if (!handled) { handled = true; settle(2, reason); } });
                    } catch (thenableError) {
                        if (!handled) { handled = true; settle(2, thenableError); }
                    }
                    return;
                }
            }

            state = newState;
            settledValue = value;

            for (var i = 0; i < handlers.length; i += 1) {
                runHandler(handlers[i]);
            }
            handlers = [];
        }

        function resolve(param) {
            /// <summary>
            /// Called by the executor function when the operation has succeeded.
            /// </summary>
            /// <param name="param">A result value passed to the then() function.</param>
            settle(1, param);
        }

        function reject(param) {
            /// <summary>
            /// Called by the executor function when the operation has failed.
            /// </summary>
            /// <param name="param">A reason value passed to the catch() function.</param>
            settle(2, param);
        }

        this.then = function(onCompleted, onRejected) {

            var resolveNext, rejectNext;

            // tslint:disable-next-line: no-shadowed-variable
            var nextPromise = new Promise(function(resolve, reject) {
                resolveNext = resolve;
                rejectNext = reject;
            });

            var handler = {
                onCompleted: (typeof onCompleted === "function") ? onCompleted : null,
                onRejected: (typeof onRejected === "function") ? onRejected : null,
                resolveNext: resolveNext,
                rejectNext: rejectNext
            };

            // Run immediately if already settled, otherwise queue until it is.
            if (state === 0) {
                handlers.push(handler);
            } else {
                runHandler(handler);
            }

            return nextPromise;
        };

        // tslint:disable-next-line: no-string-literal
        this["catch"] = function(onRejected) {
            return this.then(null, onRejected);
        };

        // Call the executor function passing the resolve & reject functions of
        // this instance. A throw from the executor rejects the promise.
        try {
            executor(resolve, reject);
        } catch (executorError) {
            reject(executorError);
        }

        return;
    };

    //#region static methods

    Promise.all = function(promiseArray) {
        /// <summary>
        /// Joins two or more promises and returns only when all the specified promises have completed or been rejected.
        /// </summary>
        /// <param name="promiseArray" type="Array">Array of promises.</param>
        /// <returns type="Promise">Returns a Promise.</returns>

        var results = [],
            resultCount = 0,
            promiseAll;

        //  Generates a then function for each promise
        function then(index, resolve) {

            return function(result) {

                // We want the results to have the same results index as it was passed in.
                results[index] = result;

                // If all of the promises have returned results, call the resolve function
                // with the results array.
                resultCount += 1;
                if (resultCount === promiseArray.length) {
                    resolve(results);
                }
            };
        }

        // Create a new Promise to return. It's resolve function will call then()
        // on each promise in the arguments list.
        promiseAll = new Promise(

            function(resolve, reject) {

                var i;

                function r(reason) { reject(reason); }

                for (i = 0; i < promiseArray.length; i += 1) {

                    if (promiseArray[i].then) {
                        promiseArray[i].then(then(i, resolve));
                        // If a promise fails, return the reason
                        // tslint:disable-next-line: no-string-literal
                        promiseArray[i]["catch"](r);
                        continue;
                    }
                    // Item is not a promise. Return a resolved promise
                    Promise.resolve(promiseArray[i]).then(then(i, resolve));
                }
            });

        return promiseAll;
    };

    Promise.race = function(promiseArray) {
        /// <summary>
        /// Creates a new promise that will resolve or reject with the same result value
        /// as the first promise to resolve or reject among the passed in arguments.
        /// </summary>
        /// <param name="promises" type="Array">Required. One or more promises.</param>
        /// <returns type="Promise">Result of first promise to resolve or fail.</returns>

        var resolved = false,
            promiseRace;

        //  Generates a then function for each promise
        function then(resolveFunction) {

            return function(result) {

                // When the first promise succeeds/fails, return the answer and ignore the rest.
                if (!resolved) {
                    resolved = true;
                    resolveFunction(result);
                }
            };
        }

        // Create a new Promise to return. It's resolve function will call then()
        // on each promise in the arguments list.
        promiseRace = new Promise(

            function(resolve, reject) {

                for (var i = 0; i < promiseArray.length; i += 1) {
                    promiseArray[i].then(then(resolve), then(reject));
                }
            });

        return promiseRace;
    };

    Promise.reject = function(rejectReason) {
        /// <summary>
        /// Creates a new rejected promise with a result equal to the passed in argument.
        /// </summary>
        /// <param name="rejectReason" type="">Required. The reason why the promise was rejected.</param>
        /// <returns type=""></returns>

        return new Promise(
            function(resolve, reject) {
                reject(rejectReason);
            });
    };

    Promise.resolve = function(resolveResult) {
        /// <summary>
        /// Creates a new resolved promise with a result equal to its argument.
        /// </summary>
        /// <param name="resolveResult" type="">Required. The value returned with the completed promise.</param>
        /// <returns type=""></returns>

        return new Promise(
            function(resolve, reject) {
                resolve(resolveResult);
            });
    };

    //#endregion static methods

    return Promise;

}));
