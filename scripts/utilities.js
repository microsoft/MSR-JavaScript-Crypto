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

// tslint:disable: no-bitwise

var msrcryptoUtilities = (function() {

    var encodingChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    var setterSupport = (function() {
        try {
            Object.defineProperty({}, "oncomplete", {});
            return true;
        } catch (ex) {
            return false;
        }
    }());

    function consoleLog(text) {
        /// <signature>
        ///     <summary>Logs a message to the debug console if the console is available.</summary>
        ///     <param name="text" type="String">console message</param>
        /// </signature>
        // tslint:disable-next-line: no-console
        if ("console" in self && "log" in console) { console.log(text); }
    }

    function toBase64(data, base64Url) {
        /// <signature>
        ///     <summary>Convert Array of bytes to a Base64 string.</summary>
        ///     <param name="data" type="Array">Byte values (numbers 0-255)</param>
        ///     <param name="base64Url" type="Boolean" optional="true">Return Base64Url encoding (this is different
        ///       from Base64 encoding.)</param >
        ///     <returns type="String" />
        /// </signature>
        /// <signature>
        ///     <summary>Convert Array of bytes to a Base64 string.</summary>
        ///     <param name="data" type="Uint8Array">Byte values (numbers 0-255)</param>
        ///     <param name="base64Url" type="Boolean" optional="true">Return Base64Url encoding (this is different
        ///       from Base64 encoding.)</param >
        ///     <returns type="String" />
        /// </signature>
        /// <signature>
        ///     <summary>Convert Array of bytes to a Base64 string.</summary>
        ///     <param name="data" type="ArrayBuffer">Byte values (numbers 0-255)</param>
        ///     <param name="base64Url" type="Boolean" optional="true">Return Base64Url encoding
        ///       (this is different from Base64 encoding.)</param >
        ///     <returns type="String" />
        /// </signature>

        var dataType = getObjectType(data);

        if (dataType !== "Array" && dataType !== "Uint8Array" && dataType !== "ArrayBuffer") {
            throw new Error("invalid input");
        }

        var output = "";
        var input = toArray(data);

        if (!base64Url) {
            base64Url = false;
        }

        var char1, char2, char3, enc1, enc2, enc3, enc4;
        var i;

        for (i = 0; i < input.length; i += 3) {

            // Get the next three chars.
            char1 = input[i];
            char2 = input[i + 1];
            char3 = input[i + 2];

            // Encode three bytes over four 6-bit values.
            // [A7,A6,A5,A4,A3,A2,A1,A0][B7,B6,B5,B4,B3,B2,B1,B0][C7,C6,C5,C4,C3,C2,C1,C0].
            // [A7,A6,A5,A4,A3,A2][A1,A0,B7,B6,B5,B4][B3,B2,B1,B0,C7,C6][C5,C4,C3,C2,C1,C0].

            // 'enc1' = high 6-bits from char1
            enc1 = char1 >> 2;
            // 'enc2' = 2 low-bits of char1 + 4 high-bits of char2
            enc2 = ((char1 & 0x3) << 4) | (char2 >> 4);
            // 'enc3' = 4 low-bits of char2 + 2 high-bits of char3
            enc3 = ((char2 & 0xF) << 2) | (char3 >> 6);
            // 'enc4' = 6 low-bits of char3
            enc4 = char3 & 0x3F;

            // 'char2' could be 'nothing' if there is only one char left to encode
            //   if so, set enc3 & enc4 to 64 as padding.
            if (isNaN(char2)) {
                enc3 = enc4 = 64;

                // If there was only two chars to encode char3 will be 'nothing'
                //   set enc4 to 64 as padding.
            } else if (isNaN(char3)) {
                enc4 = 64;
            }

            // Lookup the base-64 value for each encoding.
            output = output +
                encodingChars.charAt(enc1) +
                encodingChars.charAt(enc2) +
                encodingChars.charAt(enc3) +
                encodingChars.charAt(enc4);

        }

        if (base64Url) {
            return output.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
        }

        return output;
    }

    function base64ToBytes(encodedString) {
        /// <signature>
        ///     <summary>Converts a Base64/Base64Url string to an Array</summary>
        ///     <param name="encodedString" type="String">A Base64/Base64Url encoded string</param>
        ///     <returns type="Array" />
        /// </signature>

        // This could be encoded as base64url (different from base64)
        encodedString = encodedString.replace(/-/g, "+").replace(/_/g, "/");

        // In case the padding is missing, add some.
        while (encodedString.length % 4 !== 0) {
            encodedString += "=";
        }

        var output = [];
        var char1, char2, char3;
        var enc1, enc2, enc3, enc4;
        var i;

        // Remove any chars not in the base-64 space.
        encodedString = encodedString.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        for (i = 0; i < encodedString.length; i += 4) {

            // Get 4 characters from the encoded string.
            enc1 = encodingChars.indexOf(encodedString.charAt(i));
            enc2 = encodingChars.indexOf(encodedString.charAt(i + 1));
            enc3 = encodingChars.indexOf(encodedString.charAt(i + 2));
            enc4 = encodingChars.indexOf(encodedString.charAt(i + 3));

            // Convert four 6-bit values to three 8-bit characters.
            // [A7,A6,A5,A4,A3,A2][A1,A0, B7,B6,B5,B4][B3,B2,B1,B0, C7,C6][C5,C4,C3,C2,C1,C0].
            // [A7,A6,A5,A4,A3,A2, A1,A0][B7,B6,B5,B4, B3,B2,B1,B0][C7,C6, C5,C4,C3,C2,C1,C0].

            // 'char1' = all 6 bits of enc1 + 2 high-bits of enc2.
            char1 = (enc1 << 2) | (enc2 >> 4);
            // 'char2' = 4 low-bits of enc2 + 4 high-bits of enc3.
            char2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            // 'char3' = 2 low-bits of enc3 + all 6 bits of enc4.
            char3 = ((enc3 & 3) << 6) | enc4;

            // Convert char1 to string character and append to output
            output.push(char1);

            // 'enc3' could be padding
            //   if so, 'char2' is ignored.
            if (enc3 !== 64) {
                output.push(char2);
            }

            // 'enc4' could be padding
            //   if so, 'char3' is ignored.
            if (enc4 !== 64) {
                output.push(char3);
            }

        }

        return output;

    }

    function getObjectType(object) {
        /// <signature>
        ///     <summary>Returns the name of an object type</summary>
        ///     <param name="object" type="Object"></param>
        ///     <returns type="String" />
        /// </signature>

        return Object.prototype.toString.call(object).slice(8, -1);
    }

    function bytesToHexString(bytes, separate) {
        /// <signature>
        ///     <summary>Converts an Array of bytes values (0-255) to a Hex string</summary>
        ///     <param name="bytes" type="Array"/>
        ///     <param name="separate" type="Boolean" optional="true">Inserts a separator for display purposes
        ///       (default = false)</param >
        ///     <returns type="String" />
        /// </signature>

        var result = "";
        if (typeof separate === "undefined") {
            separate = false;
        }

        for (var i = 0; i < bytes.length; i++) {

            if (separate && (i % 4 === 0) && i !== 0) {
                result += "-";
            }

            var hexval = bytes[i].toString(16).toUpperCase();
            // Add a leading zero if needed.
            if (hexval.length === 1) {
                result += "0";
            }

            result += hexval;
        }

        return result;
    }

    function bytesToInt32(bytes, index) {
        /// <summary>
        /// Converts four bytes to a 32-bit int
        /// </summary>
        /// <param name="bytes">The bytes to convert</param>
        /// <param name="index" optional="true">Optional starting point</param>
        /// <returns type="Number">32-bit number</returns>
        index = (index || 0);

        return (bytes[index] << 24) |
            (bytes[index + 1] << 16) |
            (bytes[index + 2] << 8) |
            bytes[index + 3];
    }

    function hexToBytesArray(hexString) {
        /// <signature>
        ///     <summary>Converts a Hex-String to an Array of byte values (0-255)</summary>
        ///     <param name="hexString" type="String"/>
        ///     <returns type="Array" />
        /// </signature>

        hexString = hexString.replace(/\-/g, "");

        var result = [];
        while (hexString.length >= 2) {
            result.push(parseInt(hexString.substring(0, 2), 16));
            hexString = hexString.substring(2, hexString.length);
        }

        return result;
    }

    function clone(object) {
        /// <signature>
        ///     <summary>Creates a shallow clone of an Object</summary>
        ///     <param name="object" type="Object"/>
        ///     <returns type="Object" />
        /// </signature>

        var newObject = {};
        for (var propertyName in object) {
            if (object.hasOwnProperty(propertyName)) {
                newObject[propertyName] = object[propertyName];
            }
        }
        return newObject;
    }

    function unpackData(base64String, arraySize, toUint32s) {
        /// <signature>
        ///     <summary>Unpacks Base64 encoded data into arrays of data.</summary>
        ///     <param name="base64String" type="String">Base64 encoded data</param>
        ///     <param name="arraySize" type="Number" optional="true">Break data into sub-arrays of a given
        ///       length</param >
        ///     <param name="toUint32s" type="Boolean" optional="true">Treat data as 32-bit data instead of byte
        ///       data</param >
        ///     <returns type="Array" />
        /// </signature>

        var bytes = base64ToBytes(base64String),
            data = [],
            i;

        if (isNaN(arraySize)) {
            return bytes;
        } else {
            for (i = 0; i < bytes.length; i += arraySize) {
                data.push(bytes.slice(i, i + arraySize));
            }
        }

        if (toUint32s) {
            for (i = 0; i < data.length; i++) {
                data[i] = (data[i][0] << 24) + (data[i][1] << 16) + (data[i][2] << 8) + data[i][3];
            }
        }

        return data;
    }

    function int32ToBytes(int32) {
        /// <signature>
        ///     <summary>Converts a 32-bit number to an Array of 4 bytes</summary>
        ///     <param name="int32" type="Number">32-bit number</param>
        ///     <returns type="Array" />
        /// </signature>
        return [(int32 >>> 24) & 255, (int32 >>> 16) & 255, (int32 >>> 8) & 255, int32 & 255];
    }

    function int32ArrayToBytes(int32Array) {
        /// <signature>
        ///     <summary>Converts an Array 32-bit numbers to an Array bytes</summary>
        ///     <param name="int32Array" type="Array">Array of 32-bit numbers</param>
        ///     <returns type="Array" />
        /// </signature>

        var result = [];
        for (var i = 0; i < int32Array.length; i++) {
            result = result.concat(int32ToBytes(int32Array[i]));
        }
        return result;
    }

    function xorVectors(a, b, res) {
        /// <signature>
        ///     <summary>Exclusive OR (XOR) two arrays.</summary>
        ///     <param name="a" type="Array">Input array.</param>
        ///     <param name="b" type="Array">Input array.</param>
        ///     <param name="c" type="Array" optional="true">Optional result array.</param>
        ///     <returns type="Array">XOR of the two arrays. The length is minimum of the two input array lengths.
        ///     </returns>
        /// </signature>

        var length = Math.min(a.length, b.length),
            res = res || new Array(length);
        for (var i = 0; i < length; i += 1) {
            res[i] = a[i] ^ b[i];
        }
        return res;
    }

    function getVector(length, fillValue) {
        /// <signature>
        ///     <summary>Get an array filled with zeros (or optional fillValue.)</summary>
        ///     <param name="length" type="Number">Requested array length.</param>
        ///     <param name="fillValue" type="Number" optional="true"></param>
        ///     <returns type="Array"></returns>
        /// </signature>

        // Use a default value of zero
        if (isNaN(fillValue)) { fillValue = 0; }

        var res = new Array(length);
        for (var i = 0; i < length; i += 1) {
            res[i] = fillValue;
        }
        return res;
    }

    function toArray(typedArray) {
        /// <signature>
        ///     <summary>Converts a UInt8Array to a regular JavaScript Array</summary>
        ///     <param name="typedArray" type="UInt8Array"></param>
        ///     <returns type="Array"></returns>
        /// </signature>

        // If undefined or null return an empty array
        if (!typedArray) {
            return [];
        }

        // If already an Array return it
        if (typedArray.pop) {
            return typedArray;
        }

        // If it's an ArrayBuffer, convert it to a Uint8Array first
        if (getObjectType(typedArray) === "ArrayBuffer") {
            typedArray = new Uint8Array(typedArray);
        } else if (typedArray.BYTES_PER_ELEMENT > 1) {
            typedArray = new Uint8Array(typedArray.buffer);
        }

        // A single element array will cause a new Array to be created with the length
        // equal to the value of the single element. Not what we want.
        // We'll return a new single element array with the single value.
        if (typedArray.length === 1) { return [typedArray[0]]; }

        if (typedArray.length < 65536) { return Array.apply(null, typedArray); }

        // Apply() can only accept an array up to 65536, so we have to loop if bigger.
        var returnArray = new Array(typedArray.length);
        for (var i = 0; i < typedArray.length; i++) {
            returnArray[i] = typedArray[i];
        }

        return returnArray;

    }

    function padEnd(array, value, finalLength) {
        /// <signature>
        ///     <summary>Pads the end of an array with a specified value</summary>
        ///     <param name="array" type="Array"></param>
        ///     <param name="value" type="Number">The value to pad to the array</param>
        ///     <param name="finalLength" type="Number">The final resulting length with padding</param>
        ///     <returns type="Array"></returns>
        /// </signature>

        while (array.length < finalLength) {
            array.push(value);
        }

        return array;
    }

    function padFront(array, value, finalLength) {
        /// <signature>
        ///     <summary>Pads the front of an array with a specified value</summary>
        ///     <param name="array" type="Array"></param>
        ///     <param name="value" type="Number">The value to pad to the array</param>
        ///     <param name="finalLength" type="Number">The final resulting length with padding</param>
        ///     <returns type="Array"></returns>
        /// </signature>

        while (array.length < finalLength) {
            array.unshift(value);
        }

        return array;
    }

    function arraysEqual(array1, array2) {
        /// <signature>
        ///     <summary>Checks if two Arrays are equal by comparing their values.</summary>
        ///     <param name="array1" type="Array"></param>
        ///     <param name="array2" type="Array"></param>
        ///     <returns type="Array"></returns>
        /// </signature>

        var result = true;

        if (array1.length !== array2.length) {
            result = false;
        }

        for (var i = 0; i < array1.length; i++) {
            if (array1[i] !== array2[i]) {
                result = false;
            }
        }

        return result;
    }

    function checkParam(param, type, errorMessage) {

        if (!param) {
            throw new Error(errorMessage);
        }

        if (type && (getObjectType(param) !== type)) {
            throw new Error(errorMessage);
        }

        return true;
    }

    function stringToBytes(text) {
        /// <signature>
        ///     <summary>Converts a String to an Array of byte values (0-255).
        ///              Supports UTF-8 encoding.
        ///     </summary>
        ///     <param name="text" type="String"/>
        ///     <returns type="Array" />
        /// </signature>

        var encodedBytes = [];

        for (var i = 0, j = 0; i < text.length; i++) {

            var charCode = text.charCodeAt(i);

            if (charCode < 128) {
                encodedBytes[j++] = charCode;

            } else if (charCode < 2048) {
                encodedBytes[j++] = (charCode >>> 6) | 192;
                encodedBytes[j++] = (charCode & 63) | 128;

            } else if (charCode < 0xD800 || charCode > 0xDFFF) {
                encodedBytes[j++] = (charCode >>> 12) | 224;
                encodedBytes[j++] = ((charCode >>> 6) & 63) | 128;
                encodedBytes[j++] = (charCode & 63) | 128;

            } else {// surrogate pair (charCode >= 0xD800 && charCode <= 0xDFFF)
                charCode = ((charCode - 0xD800) * 0x400) + (text.charCodeAt(++i) - 0xDC00) + 0x10000;
                encodedBytes[j++] = (charCode >>> 18) | 240;
                encodedBytes[j++] = ((charCode >>> 12) & 63) | 128;
                encodedBytes[j++] = (charCode >>> 6) & 63 | 128;
                encodedBytes[j++] = (charCode & 63) | 128;
            }
        }

        return encodedBytes;
    }

    function bytesToString(textBytes) {
        /// <signature>
        ///     <summary>Converts an Array of byte values (0-255) to a String (Supports UTF-8 encoding)</summary>
        ///     <param name="textBytes" type="Array"/>
        ///     <returns type="String" />
        /// </signature>

        var result = "",
            charCode;

        // Convert from ArrayBuffer or Uint array if needed
        textBytes = toArray(textBytes);

        for (var i = 0; i < textBytes.length;) {

            var encodedChar = textBytes[i++];

            if (encodedChar < 128) {
                charCode = encodedChar;

            } else if (encodedChar < 224) {
                charCode = (encodedChar << 6) + textBytes[i++] - 0x3080;

            } else if (encodedChar < 240) {
                charCode =
                    (encodedChar << 12) + (textBytes[i++] << 6) + textBytes[i++] - 0xE2080;

            } else {
                charCode =
                    (encodedChar << 18) + (textBytes[i++] << 12) + (textBytes[i++] << 6) + textBytes[i++] - 0x3C82080;
            }

            // Four byte UTF-8; Convert to UTF-16 surrogate pair
            if (charCode > 0xFFFF) {
                var surrogateHigh = Math.floor((charCode - 0x10000) / 0x400) + 0xD800;
                var surrogateLow = ((charCode - 0x10000) % 0x400) + 0xDC00;
                result += String.fromCharCode(surrogateHigh, surrogateLow);
                continue;
            }

            result += String.fromCharCode(charCode);
        }

        return result;
    }

    function error(name, message) {
        var err = Error(message);
        err.name = name;
        throw err;
    }

    function isBytes(array) {
        if(!(array instanceof Array)) return false;
        for (var i = 0; i < array.length; i++) {
            var d = array[i];
            if (!isInteger(d) || d > 255 || d < 0) return false;
        }
        return true;
    }

    function isInteger(value) {
        return typeof value === "number" && isFinite(value) && Math.floor(value) === value;
    }; 
    
    function createProperty (parentObject, propertyName, initialValue, getterFunction, setterFunction) {
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

    return {
        consoleLog: consoleLog,
        toBase64: toBase64,
        fromBase64: base64ToBytes,
        checkParam: checkParam,
        getObjectType: getObjectType,
        bytesToHexString: bytesToHexString,
        bytesToInt32: bytesToInt32,
        stringToBytes: stringToBytes,
        bytesToString: bytesToString,
        unpackData: unpackData,
        hexToBytesArray: hexToBytesArray,
        int32ToBytes: int32ToBytes,
        int32ArrayToBytes: int32ArrayToBytes,
        toArray: toArray,
        arraysEqual: arraysEqual,
        clone: clone,
        xorVectors: xorVectors,
        padEnd: padEnd,
        padFront: padFront,
        getVector: getVector,
        error: error,
        isBytes: isBytes,
        isInteger: isInteger,
        createProperty: createProperty
    };

})();

/* commonjs-block */
if(typeof exports === "object") {
    module.exports = msrcryptoUtilities;
}
/* end-commonjs-block */