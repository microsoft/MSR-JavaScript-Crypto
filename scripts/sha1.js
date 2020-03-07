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
var msrcryptoSha1 = (function() {

    // tslint:disable-next-line: no-shadowed-variable
    function hashBlock(message, blockIndex, hv, k, w) {
        /// <summary>
        /// Block function for hashing algorithm to use.
        /// </summary>
        /// <param name="message" type="Array">Block data to hash</param>
        /// <param name="blockIndex" type="Number">The block of the data to hash</param>
        /// <param name="hv" type="Array">Initial hash values</param>
        /// <param name="k" type="Array">K constants</param>
        /// <param name="w" type="Array">Buffer for w values</param>
        /// <returns type="Array">Updated initial hash values</returns>

        var t, i, temp, x0, blockSize = 64, mask = 0xFFFFFFFF;

        var ra = hv[0],
            rb = hv[1],
            rc = hv[2],
            rd = hv[3],
            re = hv[4];

        // 0 ≤ t ≤ 15
        for (i = 0; i < 16; i++) {
            w[i] = utils.bytesToInt32(message, blockIndex * blockSize + i * 4);
        }

        // 16 ≤ t ≤ 79
        for (t = 16; t < 80; t++) {
            x0 = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = (x0 << 1) | (x0 >>> 31);
        }

        for (i = 0; i < 80; i++) {

            // Ch(x, y, z)=(x & y) ^ (~x & z)
            temp = ((ra << 5) | (ra >>> 27));

            temp +=
                i >= 60 ? (rb ^ rc ^ rd) :
                i >= 40 ? ((rb & rc) ^ (rb & rd) ^ (rc & rd)) :
                i >= 20 ? (rb ^ rc ^ rd) :
                /*i<=20*/ ((rb & rc) ^ ((~rb) & rd));

            temp += (re + k[i] + w[i]);

            re = rd;
            rd = rc;
            rc = ((rb << 30) | (rb >>> 2));
            rb = ra;
            ra = temp;
        }

        // Update the hash values
        hv[0] += ra & mask;
        hv[1] += rb & mask;
        hv[2] += rc & mask;
        hv[3] += rd & mask;
        hv[4] += re & mask;

        return hv;
    }

    var utils = msrcryptoUtilities,
        upd = utils.unpackData,
        h = upd("Z0UjAe/Nq4mYutz+EDJUdsPS4fA=", 4, 1),
        // tslint:disable-next-line: max-line-length
        k = upd("WoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroY8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdY", 4, 1),
        der = upd("MCEwCQYFKw4DAhoFAAQU");

    return {
        sha1: function() {
            return msrcryptoSha("SHA-1", der, h, k, 64, hashBlock, 160);
        }
    };

})();

if (typeof operations !== "undefined") {

    msrcryptoSha1.instances = {};

    msrcryptoSha1.getInstance = function(id) {
        return msrcryptoSha1.instances[id] || (msrcryptoSha1.instances[id] = msrcryptoSha1.sha1());
    };

    msrcryptoSha1.deleteInstance = function(id) {
        msrcryptoSha1.instances[id] = null;
        delete msrcryptoSha1.instances[id];
    };

    msrcryptoSha1.hash = function(/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha1.sha1.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha1.sha1.finish();
        }

        return msrcryptoSha1.sha1().computeHash(p.buffer);

    };

    operations.register("digest", "sha-1", msrcryptoSha1.hash);

}

msrcryptoHashFunctions["sha-1"] = msrcryptoSha1.sha1;
