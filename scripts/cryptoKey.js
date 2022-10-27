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

var MsrCryptoKey = (function (NativeCryptoKey) {
    var defineProperty = function (obj, name, value) {
        try {
            Object.defineProperty(obj, name, {
                enumerable: true,
                configurable: false,
                get: function () {
                    return value;
                },
            });
        } catch (e) {
            // Fallback for very old browsers (IE <= 8).
            obj[name] = value;
        }
    };

    function CryptoKey(params) {
        defineProperty(this, 'type', params.type);
        defineProperty(this, 'algorithm', params.algorithm);
        defineProperty(this, 'extractable', params.extractable);
        defineProperty(this, 'usages', params.usages ? params.usages.slice() : params.usages);
    }

    // Ensure it extends the native CryptoKey interface, so `instanceof` works.
    if (NativeCryptoKey) {
        CryptoKey.prototype = NativeCryptoKey.prototype;
    }

    return CryptoKey;
})(CryptoKey);
