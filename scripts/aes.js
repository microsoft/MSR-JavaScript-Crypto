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

var msrcryptoBlockCipher = (function() {

    var aesConstants,
        x2,
        x3,
        x14,
        x13,
        x11,
        x9,
        sBoxTable,
        invSBoxTable,
        rConTable;

    return {

        /// <summary>Advanced Encryption Standard implementation per FIPS 197.</summary>
        aes: function( /*@type(Array)*/ keyBytes) {

            // Set up the constants the first time we create an AES object only.
            if (!aesConstants) {
                // tslint:disable-next-line: max-line-length
                aesConstants = msrcryptoUtilities.unpackData("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v0CjnoHz1/t84zmCmy//hzSOQ0TE3unLVHuUMqbCIz3uTJULQvrDTgguoWYo2SSydluiSW2L0SVy+PZkhmiYFtSkXMxdZbaSbHBIUP3tudpeFUZXp42dhJDYqwCMvNMK9+RYBbizRQbQLB6Pyj8PAsGvvQMBE4prOpERQU9n3OqX8s/O8LTmc5asdCLnrTWF4vk36Bx1325H8RpxHSnFiW+3Yg6qGL4b/FY+S8bSeSCa28D+eM1a9B/dqDOIB8cxsRIQWSeA7F9gUX+pGbVKDS3lep+TyZzvoOA7Ta4q9bDI67s8g1OZYRcrBH66d9Ym4WkUY1UhDH2NAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuN", 256, false);
                x2 = aesConstants[0];
                x3 = aesConstants[1];
                x14 = aesConstants[2];
                x13 = aesConstants[3];
                x11 = aesConstants[4];
                x9 = aesConstants[5];
                sBoxTable = aesConstants[6];
                invSBoxTable = aesConstants[7];
                rConTable = aesConstants[8];
            }

            var blockSize = 128,
                keyLength,
                nK,
                nB = 4,
                nR,
                key;

            keyLength = keyBytes.length * 8;

            switch (keyLength) {
                case 128:
                case 192:
                case 256:
                    break;
                default:
                    throw new Error("Unsupported keyLength");
            }

            nK = keyLength / 32;
            nR = nK + 6;

            var shiftRows = function(a) {
                var tmp = a[1]; a[1] = a[5]; a[5] = a[9]; a[9] = a[13]; a[13] = tmp;
                tmp = a[2]; a[2] = a[10]; a[10] = tmp;
                tmp = a[6]; a[6] = a[14]; a[14] = tmp;
                tmp = a[15]; a[15] = a[11]; a[11] = a[7]; a[7] = a[3]; a[3] = tmp;
            };

            var invShiftRows = function(a) {
                var tmp = a[13]; a[13] = a[9]; a[9] = a[5]; a[5] = a[1]; a[1] = tmp;
                tmp = a[10]; a[10] = a[2]; a[2] = tmp;
                tmp = a[14]; a[14] = a[6]; a[6] = tmp;
                tmp = a[3]; a[3] = a[7]; a[7] = a[11]; a[11] = a[15]; a[15] = tmp;
            };

            var mixColumns = function(state) {
                /// <summary>Operates on the state column by column, performing a multiplication by x^4 + 1 in
                ///          GF(2 ^ 8)</summary >
                /// <param name="state" type="Array"> the current state (length 16)</param>
                /// <returns type="Array">The mixed state</returns>
                var a = state[0], b = state[1], c = state[2], d = state[3],
                    e = state[4], f = state[5], g = state[6], h = state[7],
                    i = state[8], j = state[9], k = state[10], l = state[11],
                    m = state[12], n = state[13], o = state[14], p = state[15];

                state[0] = x2[a] ^ x3[b] ^ c ^ d;
                state[1] = a ^ x2[b] ^ x3[c] ^ d;
                state[2] = a ^ b ^ x2[c] ^ x3[d];
                state[3] = x3[a] ^ b ^ c ^ x2[d];
                state[4] = x2[e] ^ x3[f] ^ g ^ h;
                state[5] = e ^ x2[f] ^ x3[g] ^ h;
                state[6] = e ^ f ^ x2[g] ^ x3[h];
                state[7] = x3[e] ^ f ^ g ^ x2[h];
                state[8] = x2[i] ^ x3[j] ^ k ^ l;
                state[9] = i ^ x2[j] ^ x3[k] ^ l;
                state[10] = i ^ j ^ x2[k] ^ x3[l];
                state[11] = x3[i] ^ j ^ k ^ x2[l];
                state[12] = x2[m] ^ x3[n] ^ o ^ p;
                state[13] = m ^ x2[n] ^ x3[o] ^ p;
                state[14] = m ^ n ^ x2[o] ^ x3[p];
                state[15] = x3[m] ^ n ^ o ^ x2[p];
            };

            var invMixColumns = function(state) {
                /// <summary>Operates on the state column by column, performing a multiplication by x^4 + 1 in
                ///          GF(2 ^ 8)</summary >
                /// <param name="state" type="Array"> the current state (length 16)</param>
                /// <returns type="Array">The mixed state</returns>
                var a = state[0], b = state[1], c = state[2], d = state[3],
                    e = state[4], f = state[5], g = state[6], h = state[7],
                    i = state[8], j = state[9], k = state[10], l = state[11],
                    m = state[12], n = state[13], o = state[14], p = state[15];

                state[0] = x14[a] ^ x11[b] ^ x13[c] ^ x9[d];
                state[1] = x9[a] ^ x14[b] ^ x11[c] ^ x13[d];
                state[2] = x13[a] ^ x9[b] ^ x14[c] ^ x11[d];
                state[3] = x11[a] ^ x13[b] ^ x9[c] ^ x14[d];
                state[4] = x14[e] ^ x11[f] ^ x13[g] ^ x9[h];
                state[5] = x9[e] ^ x14[f] ^ x11[g] ^ x13[h];
                state[6] = x13[e] ^ x9[f] ^ x14[g] ^ x11[h];
                state[7] = x11[e] ^ x13[f] ^ x9[g] ^ x14[h];
                state[8] = x14[i] ^ x11[j] ^ x13[k] ^ x9[l];
                state[9] = x9[i] ^ x14[j] ^ x11[k] ^ x13[l];
                state[10] = x13[i] ^ x9[j] ^ x14[k] ^ x11[l];
                state[11] = x11[i] ^ x13[j] ^ x9[k] ^ x14[l];
                state[12] = x14[m] ^ x11[n] ^ x13[o] ^ x9[p];
                state[13] = x9[m] ^ x14[n] ^ x11[o] ^ x13[p];
                state[14] = x13[m] ^ x9[n] ^ x14[o] ^ x11[p];
                state[15] = x11[m] ^ x13[n] ^ x9[o] ^ x14[p];
            };

            var xorWord = function(a, b) {
                return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
            };

            var addRoundKey = function(/*@type(Array)*/state, keySchedule, offset) {
                for (var i = 0; i < state.length; i += 1) {
                    state[i] ^= keySchedule[i + offset];
                }
            };

            var rotWord = function(/*@type(Array)*/word) {
                var a = word[0];
                word[0] = word[1]; word[1] = word[2]; word[2] = word[3]; word[3] = a;
            };

            var subWord = function(/*@type(Array)*/word) {
                for (var i = 0; i < word.length; i += 1) {
                    word[i] = sBoxTable[word[i]];
                }
            };

            var invSubWord = function(/*@type(Array)*/word) {
                for (var i = 0; i < word.length; i += 1) {
                    word[i] = invSBoxTable[word[i]];
                }
            };

            var getWord = function(tab, i) {
                return [tab[4 * i], tab[4 * i + 1], tab[4 * i + 2], tab[4 * i + 3]];
            };

            var setWord = function(/*@type(Array)*/left, /*@type(Array)*/right, indexL, indexR) {
                left[4 * indexL] = right[4 * indexR];
                left[4 * indexL + 1] = right[4 * indexR + 1];
                left[4 * indexL + 2] = right[4 * indexR + 2];
                left[4 * indexL + 3] = right[4 * indexR + 3];
            };

            var expandKey = function(keyIn) {
                var temp, res = [], i = 0;
                while (i < 4 * nK) {
                    res.push( keyIn[i++]);
                }

                i = nK;
                while (i < nB * (nR + 1)) {
                    temp = getWord(res, i - 1);
                    if (i % nK === 0) {
                        var index = i / nK;
                        var rcon = [rConTable[index], 0, 0, 0];
                        rotWord(temp);
                        subWord(temp);
                        temp = xorWord(temp, rcon);
                    } else if (nK > 6 && i % nK === 4) {
                        subWord(temp);
                    }
                    var newWord = xorWord(getWord(res, i - nK), temp);
                    setWord(res, newWord, i, 0);
                    i += 1;
                }
                return res;
            };

            key = expandKey(keyBytes);

            return {

                encrypt: function(dataBytes) {
                    var state = dataBytes,
                        round;

                    addRoundKey(state, key, 0);
                    for (round = 1; round <= nR - 1; round += 1) {
                        subWord(state);
                        shiftRows(state);
                        mixColumns(state);
                        addRoundKey(state, key, 4 * round * nB);
                    }
                    subWord(state);
                    shiftRows(state);
                    addRoundKey(state, key, 4 * nR * nB);

                    return state;
                },

                decrypt: function(dataBytes) {
                    var state = dataBytes,
                        round;

                    addRoundKey(state, key, 4 * nR * nB);
                    for (round = nR - 1; round >= 1; round -= 1) {
                        invShiftRows(state);
                        invSubWord(state);
                        addRoundKey(state, key, 4 * round * nB);
                        invMixColumns(state);
                    }
                    invShiftRows(state);
                    invSubWord(state);
                    addRoundKey(state, key, 0);

                    return state;
                },

                clear: function() {
                    // Reset the state
                },

                keyLength: keyLength,

                blockSize: blockSize

            };
        }

    };

})();
