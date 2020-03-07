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

var msrcryptoRsaBase = function(keyStruct) {

    var utils = msrcryptoUtilities,
        keyIsPrivate = keyStruct.hasOwnProperty("n") && keyStruct.hasOwnProperty("d"),
        keyIsCrt = keyStruct.hasOwnProperty("p") && keyStruct.hasOwnProperty("q"),
        modulusLength = keyStruct.n.length;

    function toBytes(digits) {

        var bytes = cryptoMath.digitsToBytes(digits);

        // Add leading zeros until the message is the proper length.
        utils.padFront(bytes, 0, modulusLength);

        return bytes;
    }

    function modExp(dataBytes, expBytes, modulusBytes) {
        /// <returns type="Array">Result in a digit array.</returns>
        var exponent = cryptoMath.bytesToDigits(expBytes);

        var group = cryptoMath.IntegerGroup(modulusBytes);
        var base = group.createElementFromBytes(dataBytes);
        var result = group.modexp(base, exponent);

        // var modulus = cryptoMath.bytesToDigits(modulusBytes);
        // var exponent = cryptoMath.bytesToDigits(expBytes);
        // var base = cryptoMath.bytesToDigits(dataBytes);

        // var result = cryptoMath.modExp(base, exponent, modulus);

        return result.m_digits;
    }

    function decryptModExp(cipherBytes) {

        var resultElement = modExp(cipherBytes, keyStruct.d, keyStruct.n);

        return toBytes(resultElement);
    }

    function decryptCrt(cipherBytes) {

        var b2d = cryptoMath.bytesToDigits,
            p = keyStruct.p,
            q = keyStruct.q,
            dp = keyStruct.dp,
            dq = keyStruct.dq,
            invQ = keyStruct.qi,
            pDigits = b2d(p),
            qDigits = b2d(q),
            temp = new Array(pDigits.length + qDigits.length),
            m1Digits = new Array(pDigits.length + 1),
            m2Digits = new Array(qDigits.length + 1),
            cDigits = b2d(cipherBytes),
            mm = cryptoMath.MontgomeryMultiplier,
            mmp = new mm(keyStruct.ctxp ? undefined : pDigits, keyStruct.ctxp), // pre-constructed montgomery multiplier
            mmq = new mm(keyStruct.ctxq ? undefined : qDigits, keyStruct.ctxq);

        // 'm1' = (c mod p)^dP mod p
        mmp.reduce(cDigits, temp);
        mmp.modExp(temp, b2d(dp), m1Digits);

        // 'm2' = (c mod q)^dQ mod q
        mmq.reduce(cDigits, temp);
        mmq.modExp(temp, b2d(dq), m2Digits);

        // 'diff' = (m1 - m2). Compute as follows to have |m1 - m2|.
        //      m1 - m2     if m1>=m2.
        //      m2 - m1     if m1<m2.
        // Correct the sign after modular multiplication by qInv by subtracting the product from p.
        var carry = cryptoMath.subtract(m1Digits, m2Digits, temp);
        if (carry !== 0) {
            cryptoMath.subtract(m2Digits, m1Digits, temp);
        }

        // 'h' = (m1 - m2)^qInv mod p
        cryptoMath.modMul(temp, b2d(invQ), pDigits, cDigits);
        if (carry !== 0) {
            cryptoMath.subtract(pDigits, cDigits, cDigits);
        }

        // 'm2' + q*h
        cryptoMath.multiply(cDigits, qDigits, temp);
        cryptoMath.add(m2Digits, temp, m1Digits);

        return toBytes(m1Digits);
    }

    return {

        encrypt: function(messageBytes) {

            var bytes = toBytes(modExp(messageBytes, keyStruct.e, keyStruct.n, true));
            return bytes;

        },

        decrypt: function(cipherBytes) {

            if (keyIsCrt) {
                return decryptCrt(cipherBytes);
            }

            if (keyIsPrivate) {
                return decryptModExp(cipherBytes);
            }

            throw new Error("missing private key");
        }
    };

};

var rsaShared = {

    mgf1: function(seedBytes, maskLen, hashFunction) {

        var t = [],
            bytes, hash, counter,
            hashByteLen = hashFunction.hashLen / 8;

        for (counter = 0; counter <= Math.floor(maskLen / hashByteLen); counter += 1) {

            // tslint:disable: no-bitwise
            bytes = [
                counter >>> 24 & 0xff,
                counter >>> 16 & 0xff,
                counter >>> 8 & 0xff,
                counter & 0xff
            ];
            // tslint:enable: no-bitwise

            hash = hashFunction.computeHash(seedBytes.concat(bytes));

            t = t.concat(hash);
        }

        return t.slice(0, maskLen);
    },

    checkMessageVsMaxHash: function(messageBytes, hashFunction) {

        // The max array size in JS is 2^32-1
        if (messageBytes.length > (hashFunction.maxMessageSize || 0xFFFFFFFF)) {
            throw new Error("message too long");
        }

        return;
    }

};
