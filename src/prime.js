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

var prime = (function() {

    // will be populated with small primes when needed.
    var smallPrimes = [];

    // storage of trial division remainders for each small prime
    var trialValues = [];

    // for trial division generate primes up to this:
    var MAX_SMALL_PRIMES = 4096 * 4;

    function primeSieve(max) {
        // returns an array of primes up to a specified max.
        // (i.e. all primes below max - the max does not need to be prime)

        var numbers = new Array(max + 1),
            results = [], // set this to [2] if you want all the primes
            i, j,
            limit = Math.sqrt(max) | 0;

        for (i = 3; i <= limit; i += 2) {
            for (j = i * i; j <= max; j += i * 2) {
                numbers[j] = 0;
            }
        }

        for (i = 3; i <= max; i += 2) {
            if (numbers[i] !== 0) {
                results.push(i);
            }
        }

        return results;
    }

    function incrementalTrialDivision(increment) {
        // requires setupIncrementalTrialDivision() to be called first.
        // trialValues should be pre-populated with remainders from
        // initial trial divisions of all small primes into the candidate.
        // this will perform an increment addition and mod with each remainder
        // to determine if a small prime is a divisor

        var i,
            len = trialValues.length;

        for (i = 0; i < len; i++) {
            if ((trialValues[i] + increment) % smallPrimes[i] === 0) {
                return false;
            }
        }

        return true;
    }

    function setupIncrementalTrialDivision(candidate) {

        var i, j, r, p, y,
            primeCount,
            len = candidate.length - 1,
            db = cryptoMath.DIGIT_BASE,
            h = candidate[len];

        // generate the small primes if not done already
        if (smallPrimes.length === 0) { smallPrimes = primeSieve(MAX_SMALL_PRIMES); }
        primeCount = smallPrimes.length;

        // trial values will contain a remainder for each small prime division
        trialValues = new Array(primeCount);

        for (i = 0; i < primeCount; i++) {

            j = len;
            y = smallPrimes[i];

            if (h < y) { r = h; j--; } else { r = 0; }

            while (j >= 0) {
                p = r * db + candidate[j--];
                r = p - (p / y | 0) * y;
            }

            trialValues[i] = r;
        }

        return;
    }

    // tslint:disable-next-line: variable-name
    function largestDivisibleByPowerOfTwo(number) {

        var k = 0, i = 0, s = 0, j;
        if (cryptoMath.isZero(number)) { return 0; }
        for (k = 0; number[k] === 0; k++) { /* empty */ }
        for (i = 0, j = 2; number[k] % j === 0; j *= 2, i++) {/* empty */ }
        return k * cryptoMath.DIGIT_BITS + i;
    }

    function sizeInBits(digits) {

        var k = 0, i = 0, j = 0;
        if (cryptoMath.isZero(digits)) { return 0; }
        for (k = digits.length - 1; digits[k] === 0; k--) {/* empty */ }
        for (i = cryptoMath.DIGIT_BITS - 1, j = (1 << i); i > 0; j = j >>> 1, i--) {
            if ((digits[k] & j) !== 0) {
                break;
            }
        }
        return k * cryptoMath.DIGIT_BITS + i;
    }

    // tslint:disable-next-line: variable-name
    function millerRabin(number, iterations) {

        var w = number;
        var wminus1 = [];
        cryptoMath.subtract(w, [1], wminus1);

        var a = largestDivisibleByPowerOfTwo(wminus1);

        var m = [];
        cryptoMath.shiftRight(wminus1, m, a);

        var wlen = sizeInBits(w);
        var b;
        var montmul = cryptoMath.MontgomeryMultiplier(w);

        for (var i = 1; i <= iterations; i++) {

            var status = false;

            do {
                b = getRandomOddNumber(wlen);
            } while (cryptoMath.compareDigits(b, wminus1) >= 0);

            var z = [];

            montmul.modExp(b, m, z, true);

            if (cryptoMath.compareDigits(z, [1]) === 0 || cryptoMath.compareDigits(z, wminus1) === 0) { continue; }

            for (var j = 1; j < a; j++) {

                montmul.montgomeryMultiply(z, z, z);

                if (cryptoMath.compareDigits(z, wminus1) === 0) {
                    status = true;
                    break;
                }

                if (cryptoMath.compareDigits(z, [1]) === 0) {
                    return false;
                }
            }

            if (status === false) { return false; }
        }

        return true;
    }

    function generatePrime(bits) {

        var candidate = getRandomOddNumber(bits),
            inc = 0,
            possiblePrime,
            isPrime = false,
            candidatePlusInc = [];

        setupIncrementalTrialDivision(candidate);

        while (true) {

            possiblePrime = incrementalTrialDivision(inc);

            if (possiblePrime) {
                cryptoMath.add(candidate, [inc], candidatePlusInc);
                if (millerRabin(candidatePlusInc, 6) === true) { return candidatePlusInc; }
            }

            inc += 2;
        }

    }

    function getRandomOddNumber(bits) {

        var numBytes = Math.ceil(bits / 8),
            bytes = msrcryptoPseudoRandom.getBytes(numBytes),
            digits;

        bytes[0] |= 128;
        bytes[bytes.length - 1] |= 1;

        return cryptoMath.bytesToDigits(bytes);

    }

    return {
        generatePrime: generatePrime
    };

})();
