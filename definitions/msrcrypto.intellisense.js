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

// tslint:disable: max-line-length

intellisense.annotate(msrCrypto.subtle.encrypt, function(algorithm, keyHandle, buffer) {
    /// <signature>
    /// <summary>Encrypt a UInt8Array of data. Encrypt will return an ArrayBuffer if supported, otherwise it will return a regular Array.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
    ///     <returns type="ArrayBuffer" />
    /// </signature>
    /// <signature>
    /// <summary>Encrypt an array of bytes. Encrypt will return an ArrayBuffer if supported, otherwise it will return a regular Array.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="buffer" type="Array" optional="true">An array of bytes (number from 0-255)</param>
    ///     <returns type="Array" />
    /// </signature>
    /// <signature>
    /// <summary>Encrypt an array of bytes. Encrypt will return an ArrayBuffer if supported, otherwise it will return a regular Array.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="buffer" type="Array" optional="true">A continuous array of bytes (number values from 0-255)</param>
    ///     <returns type="ArrayBuffer" />
    /// </signature>
});

intellisense.annotate(msrCrypto.subtle.decrypt, function(algorithm, keyHandle, buffer) {
    /// <signature>
    ///     <summary>Decrypt a UInt8Array of data.
    ///     Decrypt will return an ArrayBuffer if supported, otherwise it will return an Array of byte values (numbers from 0-255)</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
    ///     <returns type="Promise" />
    /// </signature>
    /// <signature>
    ///     <summary>Decrypt an array of byte values. Decrypt will return an ArrayBuffer if supported, otherwise it will return a regular Array.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
    ///     <returns type="Promise" />
    /// </signature>
});

intellisense.annotate(msrCrypto.subtle.sign, function(algorithm, keyHandle, buffer) {
    /// <signature>
    ///     <summary>Sign a UInt8Array of data.
    ///     Sign will return a signature as an ArrayBuffer if supported, otherwise it will return an Array of byte values (numbers from 0-255)</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
    ///     <returns type="Promise" />
    /// </signature>
    /// <signature>
    ///     <summary>Sign an array of byte values. Sign will return an ArrayBuffer if supported, otherwise it will return a regular Array.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
    ///     <returns type="Promise" />
    /// </signature>
});

intellisense.annotate(msrCrypto.subtle.verify, function(algorithm, keyHandle, signature, buffer) {
    /// <signature>
    ///     <summary>Verify a signature.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="signature" type="UInt8Array">UInt8Array</param>
    ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
    ///     <returns type="Promise" />
    /// </signature>
    /// <signature>
    ///     <summary>Verify a signature.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="signature" type="UInt8Array">UInt8Array</param>
    ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
    ///     <returns type="Promise" />
    /// </signature>
    /// <signature>
    ///     <summary>Verify a signature.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="signature" type="Array">An array of bytes values (numbers from 0-255)</param>
    ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
    ///     <returns type="Promise" />
    /// </signature>
    /// <signature>
    ///     <summary>Verify a signature.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="signature" type="Array">An array of bytes values (numbers from 0-255)</param>
    ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
    ///     <returns type="Promise" />
    /// </signature>
});

intellisense.annotate(msrCrypto.subtle.digest, function(algorithm, buffer) {
    /// <signature>
    ///     <summary>Digest data using a specified cryptographic hash algorithm</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
    ///     <returns type="Promise" />
    /// </signature>
    /// <signature>
    ///     <summary>Digest data using a specified cryptographic hash algorithm</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
    ///     <returns type="Promise" />
    /// </signature>
});

intellisense.annotate(msrCrypto.subtle.generateKey, function(algorithm, extractable, keyUsage) {
    /// <signature>
    ///     <summary>Generate a new key for use with the algorithm specified by the algorithm parameter</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="extractable" type="Boolean" optional="true"></param>
    ///     <param name="keyUsage" type="Array" optional="true"></param>
    ///     <returns type="Promise" />
    /// </signature>
});

intellisense.annotate(msrCrypto.subtle.deriveKey, function(algorithm, baseKey, derivedKeyType, extractable, keyUsage) {
    /// <signature>
    ///     <summary>Generate a key for the specified derivedKeyType, using the specified cryptographic key derivation algorithm with the given baseKey as input.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="baseKey" type="Key"></param>
    ///     <param name="deriveKeyType" type="Algorithm"></param>
    ///     <param name="extractable" type="Boolean" optional="true"></param>
    ///     <param name="keyUsage" type="Array" optional="true"></param>
    ///     <returns type="Promise" />
    /// </signature>
});

intellisense.annotate(msrCrypto.subtle.deriveBits, function(algorithm, baseKey, length) {
    /// <signature>
    ///     <summary>Generate an array of bytes from a given baseKey as input.</summary>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="baseKey" type="Key"></param>
    ///     <param name="length" type="Number">Number of bytes to return.</param>
    ///     <returns type="Promise" />
    /// </signature>
});

intellisense.annotate(msrCrypto.subtle.importKey, function(format, keyData, algorithm, extractable, keyUsage) {
    /// <signature>
    ///     <summary>Constructs a new Key object using the key data specified by the keyData parameter.</summary>
    ///     <param name="format" type="String"></param>
    ///     <param name="keyData" type="Array">An array of bytes values (numbers from 0-255)</param>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="extractable" type="Boolean" optional="true"></param>
    ///     <param name="keyUsage" type="Array" optional="true"></param>
    ///     <returns type="Promise" />
    /// </signature>
    /// <signature>
    ///     <summary>Constructs a new Key object using the key data specified by the keyData parameter.</summary>
    ///     <param name="format" type="String"></param>
    ///     <param name="keyData" type="UInt8Array"></param>
    ///     <param name="algorithm" type="Algorithm"></param>
    ///     <param name="extractable" type="Boolean" optional="true"></param>
    ///     <param name="keyUsage" type="Array" optional="true"></param>
    ///     <returns type="Promise" />
    /// </signature>
});

intellisense.annotate(msrCrypto.subtle.exportKey, function(format, keyHandle) {
    /// <signature>
    ///     <summary>Exports the given key material of the Key object as specified by the key parameter.</summary>
    ///     <param name="format" type="String"></param>
    ///     <param name="key" type="Key"></param>
    ///     <returns type="Promise" />
    /// </signature>

    // Export is one of the few calls where the caller does not supply an algorithm
    // since it's already part of the key to be exported.
    // So, we're pulling out of the key and adding it to the parameter set since
    // it's used as a switch to route the parameters to the right function.
    // Now we don't have to treat this as a special case in the underlying code.
});

intellisense.annotate(msrCrypto.subtle.wrapKey, function(format, key, wrappingKey, wrappingKeyAlgorithm) {
    /// <signature>
    ///     <summary>Returns a KeyOperation object which will asynchronously return an array containing the key material of key, encrypted with keyEncryptionKey using the specified keyWrappingAlgorithm.</summary>
    ///     <param name="format" type="String"></param>
    ///     <param name="key" type="Key"></param>
    ///     <param name="wrappingKey" type="Key"></param>
    ///     <param name="wrappingKeyAlgorithm" type="Algorithm"></param>
    ///     <returns type="Promise" />
    /// </signature>
});

intellisense.annotate(msrCrypto.subtle.unwrapKey, function(wrappedKey, keyAlgorithm, keyEncryptionKey, extractable, keyUsage) {
    /// <signature>
    ///     <summary>Construct a Key object from encrypted key material.</summary>
    ///     <param name="wrappedKey" type="Array">An array of bytes values (numbers from 0-255)</param>
    ///     <param name="keyAlgorithm" type="Algorithm"></param>
    ///     <param name="keyEncryptionKey" type="Key"></param>
    ///     <param name="extractable" type="Boolean" optional="true"></param>
    ///     <param name="keyUsage" type="Array" optional="true"></param>
    ///     <returns type="Promise" />
    /// </signature>
    /// <signature>
    ///     <summary>Construct a Key object from encrypted key material.</summary>
    ///     <param name="wrappedKey" type="UInt8Array"></param>
    ///     <param name="keyAlgorithm" type="Algorithm"></param>
    ///     <param name="keyEncryptionKey" type="Key"></param>
    ///     <param name="extractable" type="Boolean" optional="true"></param>
    ///     <param name="keyUsage" type="Array" optional="true"></param>
    ///     <returns type="Promise" />
    /// </signature>
});

intellisense.annotate(msrCrypto.toBase64, function(data, toBase64Url) {
    /// <signature>
    ///     <summary>Convert Array of bytes to a Base64 string.</summary>
    ///     <param name="data" type="Array">Byte values (numbers 0-255)</param>
    ///     <param name="base64Url" type="Boolean" optional="true">Return Base64Url encoding (this is different from Base64 encoding.)</param>
    ///     <returns type="String" />
    /// </signature>
    /// <signature>
    ///     <summary>Convert Array of bytes to a Base64 string.</summary>
    ///     <param name="data" type="Uint8Array">Byte values (numbers 0-255)</param>
    ///     <param name="base64Url" type="Boolean" optional="true">Return Base64Url encoding (this is different from Base64 encoding.)</param>
    ///     <returns type="String" />
    /// </signature>
    /// <signature>
    ///     <summary>Convert Array of bytes to a Base64 string.</summary>
    ///     <param name="data" type="ArrayBuffer">Byte values (numbers 0-255)</param>
    ///     <param name="base64Url" type="Boolean" optional="true">Return Base64Url encoding (this is different from Base64 encoding.)</param>
    ///     <returns type="String" />
    /// </signature>
});

intellisense.annotate(msrCrypto.fromBase64, function(base64String) {
    /// <signature>
    ///     <summary>Decode a Base64/Base64Url encoded string to an Array of bytes.</summary>
    ///     <param name="base64String" type="String">Base64 encoded string.</param>
    ///     <returns type="String" />
    /// </signature>
});

intellisense.annotate(msrCrypto.textToBytes, function(text) {
    /// <signature>
    ///     <summary>Convert UTF-8/ASCII to an Array of bytes.</summary>
    ///     <param name="text" type="String">UTF-8/ASCII text</param>
    ///     <returns type="Array" />
    /// </signature>
});

intellisense.annotate(msrCrypto.bytesToText, function(byteArray) {
    /// <signature>
    ///     <summary>Convert an Array of bytes to UTF-8/ASCII text.</summary>
    ///     <param name="byteArray" type="Array">Array of bytes.</param>
    ///     <returns type="Array" />
    /// </signature>
    /// <signature>
    ///     <summary>Convert an Array of bytes to UTF-8/ASCII text.</summary>
    ///     <param name="byteArray" type="Uint8Array">Array of bytes.</param>
    ///     <returns type="Array" />
    /// </signature>
    /// <signature>
    ///     <summary>Convert an Array of bytes to UTF-8/ASCII text.</summary>
    ///     <param name="byteArray" type="ArrayBuffer">Array of bytes.</param>
    ///     <returns type="Array" />
    /// </signature>
});

intellisense.annotate(msrCrypto.getRandomValues, function(array) {
    /// <signature>
    ///     <summary>Places cryptographically random values into the given array.</summary>
    ///     <param name="array" type="Array"></param>
    ///     <returns type="Array" />
    /// </signature>
    /// <signature>
    ///     <summary>Places cryptographically random values into the given array.</summary>
    ///     <param name="array" type="ArrayBufferView"></param>
    ///     <returns type="ArrayBufferView">Returns ArrayBufferView if supported.</returns>
    /// </signature>

});

intellisense.annotate(msrCrypto.initPrng, function(array) {
    /// <signature>
    ///     <summary>Add entropy to the PRNG.</summary>
    ///     <param name="entropyData" type="Array">Entropy input to seed or reseed the PRNG.</param>
    /// </signature>
});
