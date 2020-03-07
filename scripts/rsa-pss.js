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

var rsaMode = rsaMode || {};

rsaMode.pss = function(keyStruct, hashFunction) {
    var utils = msrcryptoUtilities,
        random = msrcryptoPseudoRandom;

    function emsa_pss_encode(messageBytes, /*@optional*/ saltLength, /*@optional*/ salt) {
        var modulusBits = cryptoMath.bitLength(keyStruct.n),
            emBits = modulusBits - 1,
            emLen = Math.ceil(emBits / 8),
            mHash = hashFunction.computeHash(messageBytes);

        saltLength = salt ? salt.length : saltLength == null ? mHash.length : saltLength;

        if (emLen < mHash.length + saltLength + 2) {
            throw new Error("encoding error");
        }

        salt = salt || random.getBytes(saltLength);

        // M' = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
        var mp = [ 0, 0, 0, 0, 0, 0, 0, 0 ].concat(mHash, salt);

        var h = hashFunction.computeHash(mp);

        var ps = utils.getVector(emLen - salt.length - h.length - 2);

        var db = ps.concat([ 1 ], salt);

        var dbMask = rsaShared.mgf1(h, emLen - h.length - 1, hashFunction);

        var maskedDb = utils.xorVectors(db, dbMask);

        // Set the ((8 * emLen) - emBits) of the leftmost octect in maskedDB to zero
        var mask = 0;
        for (var i = 0; i < 8 - (8 * emLen - emBits); i++) {
            mask += 1 << i;
        }
        maskedDb[0] &= mask;

        var em = maskedDb.concat(h, [ 0xbc ]);

        return em;
    }

    function emsa_pss_verify(signatureBytes, messageBytes, /*@optional*/ saltLength) {
        var modulusBits = cryptoMath.bitLength(keyStruct.n);

        var emBits = modulusBits - 1;

        var emLen = Math.ceil(emBits / 8);

        var mHash = hashFunction.computeHash(messageBytes);

        var hLen = mHash.length;

        saltLength = saltLength == null ? hLen : saltLength;

        if (emLen < hLen + saltLength + 2) {
            return false;
        }

        var maskedDb = signatureBytes.slice(0, emLen - hLen - 1);

        var h = signatureBytes.slice(maskedDb.length, maskedDb.length + hLen);

        var dbMask = rsaShared.mgf1(h, emLen - hLen - 1, hashFunction);

        var /*@type(Array)*/ db = utils.xorVectors(maskedDb, dbMask);

        // Set the leftmost 8 * emLen - emBits of db[0] to zero
        db[0] &= 0xff >>> (8 - (8 * emLen - emBits));

        // Verify the leftmost bytes are zero
        for (var i = 0; i < emLen - hLen - saltLength - 2; i++) {
            if (db[i] !== 0) {
                return false;
            }
        }

        if (db[emLen - hLen - saltLength - 2] !== 0x01) {
            return false;
        }

        var salt = db.slice(db.length - saltLength);

        // M' = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
        var mp = [ 0, 0, 0, 0, 0, 0, 0, 0 ].concat(mHash, salt);

        var hp = hashFunction.computeHash(mp);

        return utils.arraysEqual(hp, h);
    }

    return {
        sign   : function(messageBytes, /*@optional*/ saltLength, /*@optional*/ salt) {
            return emsa_pss_encode(messageBytes, saltLength, salt);
        },

        verify : function(signatureBytes, messageBytes, /*@optional*/ saltLength) {
            return emsa_pss_verify(signatureBytes, messageBytes, saltLength);
        }
    };
};
