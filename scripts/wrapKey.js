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
var msrcryptoWrapKey = (function() {

    var utils = msrcryptoUtilities;

    function wrapKey(params) {

        var rsaObj = msrcryptoRsa(
            params.keyData1,
            params.keyHandle1.algorithm.name,
            msrcryptoHashFunctions["SHA-1"])();

        var tagLength = 128;

        var keyToWrapJwk = msrcryptoJwk.keyToJwkOld(params.keyHandle, params.keyData);

        var jweHeader = {
            "alg": params.keyHandle1.algorithm.name.toUpperCase(),
            "enc": "A128GCM"
        };

        var encodedJweHeader =
            utils.toBase64(JSON.stringify(jweHeader), true);

        var cmk = msrcryptoPseudoRandom.getBytes(32);

        var jweEncryptedKey = rsaObj.encrypt(cmk);

        var encodedJweEncryptedKey = utils.toBase64(jweEncryptedKey, true);

        var jweIv = msrcryptoPseudoRandom.getBytes(12);

        var encodedJweIv = utils.toBase64(jweIv, true);

        var additionalData = encodedJweHeader.concat(".", encodedJweEncryptedKey, ".", encodedJweIv);

        var gcm = msrcryptoGcm(msrcryptoBlockCipher.aes(cmk));
        gcm.init(jweIv, utils.stringToBytes(additionalData), tagLength);

        var ciphertextPlusTag = gcm.encrypt(keyToWrapJwk);

        var tag = ciphertextPlusTag.slice(-(tagLength / 8));

        var encodedIntegrityValue = utils.toBase64(tag, true);

        var encodedCiphertext =
            utils.toBase64(ciphertextPlusTag.slice(0, ciphertextPlusTag.length - tag.length), true);

        var jwe = {

            recipients: [{
                header: encodedJweHeader,
                encrypted_key: encodedJweEncryptedKey,
                integrity_value: encodedIntegrityValue
            }
            ],
            initialization_vector: encodedJweIv,
            ciphertext: encodedCiphertext

        };

        return utils.stringToBytes(JSON.stringify(jwe));

    }

    function unwrapKey(params) {

        var b64Tobytes = utils.fromBase64;

        var keyDataJwk =
            JSON.parse(String.fromCharCode.apply(null, params.buffer));

        var header = utils.fromBase64(keyDataJwk.recipients[0].header);

        // tslint:disable-next-line: variable-name
        var encrypted_key =
            b64Tobytes(keyDataJwk.recipients[0].encrypted_key);

        // tslint:disable-next-line: variable-name
        var integrity_value =
            b64Tobytes(keyDataJwk.recipients[0].integrity_value);

        // tslint:disable-next-line: variable-name
        var initialization_vector =
            b64Tobytes(keyDataJwk.initialization_vector);

        var ciphertext =
            b64Tobytes(keyDataJwk.ciphertext);

        var hashFunc = msrcryptoHashFunctions["SHA-1"]();
        var rsaObj = msrcryptoRsa(params.keyData, params.keyHandle.algorithm.name, hashFunc);
        var inKey = rsaObj.decrypt(encrypted_key);

        var additionalData =
            keyDataJwk.recipients[0].header.concat(".", keyDataJwk.recipients[0].encrypted_key, ".",
                keyDataJwk.initialization_vector);

        var gcm = msrcryptoGcm(msrcryptoBlockCipher.aes(inKey));
        gcm.init(initialization_vector, utils.stringToBytes(additionalData), 128);

        var result = gcm.decrypt(ciphertext, integrity_value);

        var keyObject = msrcryptoJwk.jwkToKey(result, params.algorithm, ["k"]);

        return {
            type: "keyImport",
            keyData: keyObject.k,
            keyHandle: new MsrCryptoKey({
                algorithm: { name: params.algorithm.name },
                extractable: params.extractable || keyObject.extractable,
                usages: params.usages,
                type: "secret"
            })
        };
    }
    return {
        wrapKey: wrapKey,
        unwrapKey: unwrapKey

    };

})();
if (typeof operations !== "undefined") {
    operations.register("wrapKey", "AES-GCM", msrcryptoWrapKey.wrapKey);
    operations.register("unwrapKey", "AES-CBC", msrcryptoWrapKey.unwrapKey);
}
