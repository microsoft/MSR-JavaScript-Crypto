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

var msrcryptoSha256 = (function() {

    var utils = msrcryptoUtilities;

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

        var t, i, temp, x0, x1, blockSize = 64, mask = 0xFFFFFFFF;

        var ra = hv[0],
            rb = hv[1],
            rc = hv[2],
            rd = hv[3],
            re = hv[4],
            rf = hv[5],
            rg = hv[6],
            rh = hv[7];

        // 0 ≤ t ≤ 15
        for (i = 0; i < 16; i++) {
            w[i] = utils.bytesToInt32(message, blockIndex * blockSize + i * 4);
        }

        // 16 ≤ t ≤ 63
        for (t = 16; t < 64; t++) {

            x0 = w[t - 15];
            x1 = w[t - 2];

            w[t] = (((x1 >>> 17) | (x1 << 15)) ^ ((x1 >>> 19) | (x1 << 13)) ^ (x1 >>> 10))
                    + w[t - 7]
                    + (((x0 >>> 7) | (x0 << 25)) ^ ((x0 >>> 18) | (x0 << 14)) ^ (x0 >>> 3))
                    + w[t - 16];

            w[t] = w[t] & mask;
        }

        for (i = 0; i < 64; i++) {

            temp = rh +
                    ((re >>> 6 | re << 26) ^ (re >>> 11 | re << 21) ^ (re >>> 25 | re << 7)) +
                    ((re & rf) ^ ((~re) & rg)) +
                    k[i] + w[i];

            rd += temp;

            temp += ((ra >>> 2 | ra << 30) ^ (ra >>> 13 | ra << 19) ^ (ra >>> 22 | ra << 10)) +
                    ((ra & (rb ^ rc)) ^ (rb & rc));

            rh = rg; // 'h' = g
            rg = rf; // 'g' = f
            rf = re; // 'f' = e
            re = rd; // 'e' = d
            rd = rc; // 'd' = c
            rc = rb; // 'c' = b
            rb = ra; // 'b' = a
            ra = temp; // 'a' = temp

        }

        hv[0] = (hv[0] + ra) >>> 0;
        hv[1] = (hv[1] + rb) >>> 0;
        hv[2] = (hv[2] + rc) >>> 0;
        hv[3] = (hv[3] + rd) >>> 0;
        hv[4] = (hv[4] + re) >>> 0;
        hv[5] = (hv[5] + rf) >>> 0;
        hv[6] = (hv[6] + rg) >>> 0;
        hv[7] = (hv[7] + rh) >>> 0;

        return hv;
    }

    var k256, h224, h256, der224, der256, upd = utils.unpackData;

    h224 = upd("wQWe2DZ81QcwcN0X9w5ZOf/ACzFoWBURZPmPp776T6Q", 4, 1);

    h256 = upd("agnmZ7tnroU8bvNypU/1OlEOUn+bBWiMH4PZq1vgzRk", 4, 1);

    // tslint:disable-next-line: max-line-length
    k256 = upd("QoovmHE3RJG1wPvP6bXbpTlWwltZ8RHxkj+CpKscXtXYB6qYEoNbASQxhb5VDH3Dcr5ddIDesf6b3AanwZvxdOSbacHvvkeGD8GdxiQMocwt6SxvSnSEqlywqdx2+YjamD5RUqgxxm2wAyfIv1l/x8bgC/PVp5FHBspjURQpKWcntwqFLhshOE0sbfxTOA0TZQpzVHZqCruBwskuknIshaK/6KGoGmZLwkuLcMdsUaPRkugZ1pkGJPQONYUQaqBwGaTBFh43bAgnSHdMNLC8tTkcDLNO2KpKW5zKT2gub/N0j4LueKVjb4TIeBSMxwIIkL7/+qRQbOu++aP3xnF48g", 4, 1);

    // SHA-224 DER encoding
    // 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C
    der224 = upd("MC0wDQYJYIZIAWUDBAIEBQAEHA");

    // SHA-256 DER encoding
    // 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    der256 = upd("MDEwDQYJYIZIAWUDBAIBBQAEIA");

    return {
        sha224: function() {
            return msrcryptoSha("SHA-224", der224, h224, k256, 64, hashBlock, 224);
        },
        sha256: function() {
            return msrcryptoSha("SHA-256", der256, h256, k256, 64, hashBlock, 256);
        }
    };
})();

if (typeof operations !== "undefined") {

    // Create a new instance if there isn't already one
    msrcryptoSha256.instance224 = msrcryptoSha256.instance224 || msrcryptoSha256.sha224();
    msrcryptoSha256.instance256 = msrcryptoSha256.instance256 || msrcryptoSha256.sha256();

    // Store separate instances for each worker when using 'process' streaming
    msrcryptoSha256.instances = {};

    msrcryptoSha256.getInstance224 = function(id) {
        return msrcryptoSha256.instances[id] || (msrcryptoSha256.instances[id] = msrcryptoSha256.sha224());
    };

    msrcryptoSha256.getInstance256 = function(id) {
        return msrcryptoSha256.instances[id] || (msrcryptoSha256.instances[id] = msrcryptoSha256.sha256());
    };

    msrcryptoSha256.deleteInstance = function(id) {
        msrcryptoSha256.instances[id] = null;
        delete msrcryptoSha256.instances[id];
    };

    msrcryptoSha256.hash256 = function(/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha256.getInstance256(p.workerid).process(p.buffer);
            return null;
        }

        if (p.operationSubType === "finish") {

            var result = msrcryptoSha256.getInstance256(p.workerid).finish();
            msrcryptoSha256.deleteInstance(p.workerid);
            return result;
        }

        if (p.operationSubType === "abort") {
            msrcryptoSha256.deleteInstance(p.workerid);
            return;
        }

        return msrcryptoSha256.instance256.computeHash(p.buffer);

    };

    msrcryptoSha256.hash224 = function(/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha256.getInstance224(p.workerid).process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            var result = msrcryptoSha256.getInstance224(p.workerid).finish();
        }

        if (p.operationSubType === "abort") {
            msrcryptoSha224.deleteInstance(p.workerid);
            return;
        }

        return msrcryptoSha256.instance224.computeHash(p.buffer);

    };

    operations.register("digest", "sha-224", msrcryptoSha256.hash224);
    operations.register("digest", "sha-256", msrcryptoSha256.hash256);
}

msrcryptoHashFunctions["sha-224"] = msrcryptoSha256.sha224;
msrcryptoHashFunctions["sha-256"] = msrcryptoSha256.sha256;
