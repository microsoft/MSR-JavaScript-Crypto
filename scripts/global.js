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
/// Store the URL for this script. We will need this later to instantiate
/// new web workers (if supported).
var scriptUrl = (function() {

    if (typeof document !== "undefined") {
        // Use error.stack to find out the name of this script
        try {
            throw new Error();
        } catch (e) {
            if (e.stack) {
                var match = /\w+:\/\/(.+?\/)*.+\.js/.exec(e.stack);
                return (match && match.length > 0) ? match[0] : null;
            }
        }
    } else if (typeof self !== "undefined") {
        // If this script is being run in a WebWorker, 'document' will not exist
        //  but we can use self.
        return self.location.href;
    }

    // We must be running in an environment without document or self.
    return null;

    /* jshint +W117 */

})();

// Indication if the user provided entropy into the entropy pool.
var fprngEntropyProvided = false;

// Support for webWorkers IE10+.
var webWorkerSupport = (typeof Worker !== "undefined");

// Is this script running in an instance of a webWorker?
var runningInWorkerInstance = typeof importScripts === "function" && self instanceof WorkerGlobalScope;

// Has this worker instance been initialized
var workerInitialized = false;

// Typed Arrays support?
var typedArraySupport = (typeof ArrayBuffer !== "undefined");

// Property setter/getter support IE9+.
var setterSupport = (function() {
    try {
        Object.defineProperty({}, "oncomplete", {});
        return true;
    } catch (ex) {
        return false;
    }
}());

// We default to false in ver 1.5+  This was giving too many people problems as true by default.
// We'll run in async mode if webWorkers are supported, working, and the user enables them.
var asyncMode = false;

var createProperty = function(parentObject, propertyName, /*@dynamic*/initialValue, getterFunction, setterFunction) {
    /// <param name="parentObject" type="Object"/>
    /// <param name="propertyName" type="String"/>
    /// <param name="initialValue" type="Object"/>
    /// <param name="getterFunction" type="Function"/>
    /// <param name="setterFunction" type="Function" optional="true"/>

    if (!setterSupport) {
        parentObject[propertyName] = initialValue;
        return;
    }

    var setGet = {};

    // tslint:disable-next-line: no-unused-expression
    getterFunction && (setGet.get = getterFunction);
    // tslint:disable-next-line: no-unused-expression
    setterFunction && (setGet.set = setterFunction);

    Object.defineProperty(
        parentObject,
        propertyName, setGet);
};

// Collection of hash functions for global availability.
// Each hash function will add itself to the collection as it is evaluated.
var msrcryptoHashFunctions = {};
