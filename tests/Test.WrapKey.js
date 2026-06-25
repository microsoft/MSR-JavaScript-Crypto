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

// #region WrapKey

QUnit.module("Wrap Key");

/// Wrap an AES-CBC key with a RSA-OAEP key using msrCrypto
/// then unwrap the key using IE11 msCrypto

if (typeof msCrypto !== "undefined") {  // msCrypto is only defined in IE

    var ieCrypto = crypto;

    asyncTest("JS to IE OAEP/AES-GCM", function() {

        var encryptedData,
            encryptedData1;

        // Generate encryptionKey:
        msrCrypto.subtle.generateKey({ name: "Aes-CBC", length: 128 }, true, ["sign", "verify"]).then(

            function(encryptionKey) {

                msrCrypto.subtle.encrypt(
                    {
                        name: "Aes-CBC",
                        iv: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
                    }, encryptionKey, [1, 2, 3]).then(

                    function(e) {

                        encryptedData = shared.getArrayResult(e);

                        shared.getRsaKeyPair(
                            { name: "rSa-OAEP", modulusLength: 1024 },
                            function(keyPair) {

                                var publicKey = keyPair.keyHandlePublic;
                                var privateKey = keyPair.keyHandlePrivateIE;

                                msrCrypto.subtle.wrapKey(
                                    encryptionKey,
                                    publicKey,
                                    { name: "Aes-GCM" }).then(

                                    function(wrappedKeyData) {

                                        var key = wrappedKeyData;

                                        if (msrCrypto) {
                                            wrappedKeyData = JSON.stringify(wrappedKeyData);
                                            wrappedKeyData = shared.toBase64(wrappedKeyData);
                                            key = shared.base64ToBytes(wrappedKeyData);
                                        }

                                        var cryptoObj = ieCrypto.subtle.unwrapKey(
                                            //new Uint8Array(wrappedKeyData),
                                            key,
                                            { name: "Aes-CBC" },
                                            privateKey, true, ["encrypt", "decrypt"]);

                                        cryptoObj.oncomplete =

                                            function(e0) {

                                                var unwrappedEncryptionKey = e0.target.result;

                                                var encryptObj = ieCrypto.subtle.encrypt(
                                                    {
                                                        name: "Aes-CBC",
                                                        iv: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                                            13, 14, 15])
                                                    }, unwrappedEncryptionKey, new Uint8Array([1, 2, 3]));

                                                encryptObj.oncomplete =

                                                        function(e1) {
                                                            start();
                                                            encryptedData1 = shared.getArrayResult(e1.target.result);
                                                            equal(encryptedData.join(), encryptedData1.join(),
                                                                encryptedData.join() + "==" + encryptedData1.join());
                                                        };
                                            };
                                        cryptoObj.onerror = shared.error("unwrapKey");

                                    },
                                    shared.error("wrapKey")
                                );
                            }
                        );
                    }
                );
            }
        );
    });

    asyncTest("IE to JS OAEP/AES-GCM", function() {

        // Generate encryptionKey:
        var importOp = ieCrypto.subtle.generateKey(
        { name: "Aes-CBC", length: 128 },
        true, ["sign", "verify"]);

        importOp.oncomplete =

            function(e) {

                var encryptionKey = e.target.result;

                shared.getRsaKeyPair({ name: "rSa-OAEP", modulusLength: 1024 }, function(keyPair) {

                    var publicKey = keyPair.keyHandlePublicIE;
                    var privateKey = keyPair.keyHandlePrivate;

                    var wrapOp = ieCrypto.subtle.wrapKey(
                        encryptionKey,
                        publicKey,
                        { name: "Aes-GCM" });

                    wrapOp.oncomplete =

                        function(e0) {

                            var wrappedKeyData = e0.target.result;

                            var unWrapOp = msrCrypto.subtle.unwrapKey(
                                new Uint8Array(wrappedKeyData),
                                { name: "Aes-CBC" },
                                privateKey, true, ["encrypt", "decrypt"]).then(

                                function(e1) {
                                    start();
                                    var unwrappedEncryptionKey = ENGINE_METHOD_PKEY_ASN1_METHS;
                                    ok(true);
                                },
                                shared.error("unwrapKey")
                            );

                        };
                    wrapOp.onerror = shared.error("wrapKey");

                });
            };
    });

    asyncTest("JS to JS OAEP/AES-GCM", function() {

        // Generate encryptionKey:
        var importOp = msrCrypto.subtle.generateKey(
        { name: "Aes-CBC", length: 128 },
        true, ["sign", "verify"]).then(

            function(encryptionKey) {

                shared.getRsaKeyPair({ name: "rSa-OAEP", modulusLength: 1024 }, function(keyPair) {

                    var publicKey = keyPair.keyHandlePublic;
                    var privateKey = keyPair.keyHandlePrivate;

                    msrCrypto.subtle.wrapKey(
                        encryptionKey,
                        publicKey,
                        { name: "Aes-GCM" }).then(

                            function(wrappedKeyData) {

                                msrCrypto.subtle.unwrapKey(
                                    new Uint8Array(wrappedKeyData),
                                    { name: "Aes-CBC" },
                                    privateKey, true, ["encrypt", "decrypt"]).then(

                                function(unwrappedEncryptionKey) {
                                    start();
                                    ok(true);
                                },
                                    shared.error("unwrapKey")
                                );

                            },
                            shared.error("wrapKey")
                    );
                });
            }
        );
    });
}
// #endregion WrapKey
