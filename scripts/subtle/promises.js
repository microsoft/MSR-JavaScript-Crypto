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
// AMD/global wrapper
(function(root, factory) {

    if (typeof Promise !== "undefined") {
        return;
    }
    root.Promise = factory();

}(this, function() {

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

        var successResult = null,
            failReason = null,
            thenResolved = [],
            thenRejected = [],
            rejectThenPromise = [],
            resolveThenPromise = [];

        this.then = function(onCompleted, onRejected) {

            var thenFunctionResult;

            // If we already have a result because resolveFunction was synchronous,
            // then just call onCompleted with the result.
            if (successResult) {
                thenFunctionResult = onCompleted(successResult.result);

                if (thenFunctionResult && thenFunctionResult.then) {
                    return thenFunctionResult;
                }

                // Create a new promise; resolve with the result;
                // return the resolved promise.
                return Promise.resolve(thenFunctionResult);
            }

            // If we already have a fail reason from a rejected promise
            if (failReason) {
                thenFunctionResult = onRejected ? onRejected(failReason.result) : failReason.result;

                if (thenFunctionResult && thenFunctionResult.then) {
                    return thenFunctionResult;
                }

                // Create a new promise; reject with the result;
                // return the resolved promise.
                return Promise.resolve(thenFunctionResult);
            }

            // If we do not have a result, store the onCompleted/onRejected functions
            // to call when we do get a result.
            thenResolved.push(onCompleted);
            if (onRejected) {
                thenRejected.push(onRejected);
            }

            // Return a new promise object. This will allow chaining with then/catch().
            // tslint:disable-next-line: no-shadowed-variable
            return new Promise(function(resolve, reject) {
                resolveThenPromise.push(resolve);
                rejectThenPromise.push(reject);
            });
        };

        // tslint:disable-next-line: no-string-literal
        this["catch"] = function(onRejected) {

            var catchFunctionResult;

            // If we already have a result because resolveFunction was synchronous,
            // then just call onRejected with the result.
            if (failReason) {
                catchFunctionResult = onRejected(failReason.result);

                if (catchFunctionResult && catchFunctionResult.then) {
                    return catchFunctionResult;
                }

                return Promise.resolve(catchFunctionResult);
            }

            // If we do not have a result, store the onRejected function
            // to call when we do get a result.
            thenRejected.push(onRejected);

            // Return a new promise object. This will allow chaining with then/catch().
            // tslint:disable-next-line: no-shadowed-variable
            return new Promise(function(resolve, reject) {
                resolveThenPromise.push(resolve);
                rejectThenPromise.push(reject);
            });
        };

        function resolve(param) {
            /// <summary>
            /// Called by the executor function when the function has succeeded.
            /// </summary>
            /// <param name="param">A result value that will be passed to the then() function.</param>

            var result, i;

            // Call each attached Then function with the result
            for (i = 0; i < thenResolved.length; i += 1) {

                result = thenResolved[i](param);

                // If the result of the then() function is a Promise,
                // set then() to call the chained resolve function.
                if (result && result.then) {
                    result.then(resolveThenPromise[i]);

                    // Also set catch() if present
                    if (rejectThenPromise[i]) {
                        // tslint:disable-next-line: no-string-literal
                        result["catch"](rejectThenPromise[i]);
                    }

                } else {

                    // If a then() promise was chained to this promise, call its resolve
                    // function.
                    if (resolveThenPromise[i]) {
                        resolveThenPromise[i](result);
                    }
                }
            }

            // If the onCompleted function has not yet been assigned, store the result.
            successResult = { result: param };

            return;
        }

        function reject(param) {

            var reason, i;

            // Call each catch function on this promise
            for (i = 0; i < thenRejected.length; i += 1) {

                reason = thenRejected[i](param);

                // If the result of the catch() function is a Promise,
                // set then() to call the chained resolve function.
                if (reason && reason.then) {
                    reason.then(resolveThenPromise[i], rejectThenPromise[i]);

                } else {
                    if (resolveThenPromise[i]) {
                        resolveThenPromise[i](reason);
                    }
                }
            }

            // If the onCompleted function has not yet been assigned, store the result.
            failReason = { result: param };

            return;
        }

        // Call the executor function passing the resolve & reject functions of
        // this instance.
        executor(resolve, reject);

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
