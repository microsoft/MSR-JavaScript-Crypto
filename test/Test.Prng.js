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

// These Known Answer Tests (KAT) are taken from Windows CNG FIPS 140-2 verification effort,
// which was provided by Windows CNG FIPS certification lab (CMVP) for AES-256 no derivation function.

test("PRNG vectors", function() {
    var numberOfTests = 0, i;
    testVectors = prngKAT;
    for (i = 0; i < testVectors.length; i++) {
        numberOfTests += testVectors[i].expected.length;
    }

    // Q-unit uses the Expect() function to declare how many test assertions
    //   you expect to have. So if some bug quietly kills a function, q-unit
    //   will let you know that the expected number of asserts wasn't evaluated
    expect(numberOfTests);

    for (i = 0; i < testVectors.length; i++) {

        var seed = testVectors[i].seed;
        var personalizationString = testVectors[i].personalizationString;
        var additionalInputArray = testVectors[i].additionalInput;
        var expectedArray = testVectors[i].expected;
        var randomBytes;

        msrcryptoPseudoRandom.init(seed, personalizationString);

        for (var j = 0; j < expectedArray.length; j++) {
            var expectedBytes = expectedArray[j];
            var additionalInput = additionalInputArray[j];
            var bytesToGet = expectedBytes.length;
            randomBytes = msrcryptoPseudoRandom.getBytes(bytesToGet, additionalInput);

            // Q-unit equal assertion. Passes if 1st param equals 2nd param.
            // Using join() here to convert arrays to strings for comparison
            equal(randomBytes.join(), expectedBytes.join(),
                "Passed - Seed " + i.toString() + " Generate " + j.toString());
        }
    }
});

test("PRNG init", function() {
    var numberOfTests = 32;
    expect(numberOfTests);
    var entropy = prngKAT[0].seed.slice(0);
    var randomNumberLength = 128;

    // Initialize
    msrcryptoPseudoRandom.init(entropy);

    // Reseed multiple times, and ask for random numbers.
    for (var i = 0; i < numberOfTests; ++i) {
        msrcryptoPseudoRandom.reseed(entropy);
        msrcryptoPseudoRandom.reseed(entropy);
        msrcryptoPseudoRandom.reseed(entropy);
        msrcryptoPseudoRandom.reseed(entropy);
        entropy = msrcryptoPseudoRandom.getBytes(randomNumberLength);
        ok(true, "PRNG Init/getBytes passed [" + i.toString() + "]");
    }
});
