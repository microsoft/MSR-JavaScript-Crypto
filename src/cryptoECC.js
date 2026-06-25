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

/// cryptoECC.js ==================================================================================
/// Implementation of Elliptic Curve math routines for cryptographic applications.

function MsrcryptoECC() {
    /// <summary>Elliptic Curve Cryptography (ECC) functions.</summary>

    var btd = cryptoMath.bytesToDigits;

    // Create an array, mimics the constructors for typed arrays.
    function createArray(/*@dynamic*/parameter) {
        var i, array = null;
        if (!arguments.length || typeof arguments[0] === "number") {
            // A number.
            array = [];
            for (i = 0; i < parameter; i += 1) {
                array[i] = 0;
            }
        } else if (typeof arguments[0] === "object") {
            // An array or other index-able object
            array = [];
            for (i = 0; i < parameter.length; i += 1) {
                array[i] = parameter[i];
            }
        }
        return array;
    }

    var EllipticCurveFp = function(p1, a1, b1, order, gx, gy) {
        /// <param name="p1" type="Digits"/>
        /// <param name="a1" type="Digits"/>
        /// <param name="b1" type="Digits"/>
        /// <param name="order" type="Digits"/>
        /// <param name="gx" type="Digits"/>
        /// <param name="gy" type="Digits"/>
        /// <returns type="EllipticCurveFp"/>

        var fieldStorageBitLength = p1.length;

        var generator = EllipticCurvePointFp(this, false, gx, gy, null, false);

        return {
            p: p1,                  // field prime
            a: a1,                  // Weierstrass coefficient a
            b: b1,                  // Weierstrass coefficient b
            order: order,           // EC group order
            generator: generator,   // EC group generator
            allocatePointStorage: function() {
                return EllipticCurvePointFp(
                    this,
                    false,
                    cryptoMath.intToDigits(0, fieldStorageBitLength),
                    cryptoMath.intToDigits(0, fieldStorageBitLength)
                );
            },
            createPointAtInfinity: function() {
                return EllipticCurvePointFp(
                    this,
                    true,
                    cryptoMath.intToDigits(0, fieldStorageBitLength),
                    cryptoMath.intToDigits(0, fieldStorageBitLength)
                );
            }
        };
    };

    var createWeierstrassCurve = function(curveData) {

        var newCurve = new EllipticCurveFp(
            btd(curveData.p), // P
            btd(curveData.a), // A
            btd(curveData.b), // B
            btd(curveData.order), // Order
            btd(curveData.gx), // gX
            btd(curveData.gy)  // gy
        );

        newCurve.type = curveData.type;
        newCurve.name = curveData.name;
        newCurve.generator.curve = newCurve;

        return newCurve;
    };

    var createTedCurve = function(curveData) {

        //var btd = cryptoMath.bytesToDigits;

        var newCurve = new EllipticCurveFp(
            btd(curveData.p), // P
            btd(curveData.a), // A
            btd(curveData.d), // D
            btd(curveData.order), // Order
            btd(curveData.gx), // gX
            btd(curveData.gy)  // gy
        );

        newCurve.type = curveData.type;

        if (newCurve.type === 1) {
            newCurve.d = newCurve.b.slice();
            delete newCurve.b;
        }

        newCurve.rbits = curveData.info[2];
        newCurve.name = curveData.name;
        newCurve.generator.curve = newCurve;

        return newCurve;
    };

    var EllipticCurvePointFp = function(curve, isInfinity, x, y, z, isInMontgomeryForm) {
        /// <param name="curve" type="EllipticCurveFp"/>
        /// <param name="isInfinity" type="Boolean"/>
        /// <param name="x" type="Digits"/>
        /// <param name="y" type="Digits"/>
        /// <param name="z" type="Digits" optional="true"/>
        /// <param name="isInMontgomeryForm" type="Boolean" optional="true"/>
        /// <returns type="EllipticCurvePointFp"/>

        var returnObj;

        // 'optional' parameters
        if (typeof z === "undefined") {
            z = null;
        }

        if (typeof isInMontgomeryForm === "undefined") {
            isInMontgomeryForm = false;
        }

        function equals(/*@type(EllipticCurvePointFp)*/ellipticCurvePointFp) {
            /// <param name="ellipticCurvePointFp" type="EllipticCurvePointFp"/>

            // If null
            if (!ellipticCurvePointFp) {
                return false;
            }

            // Infinity == infinity
            if (returnObj.isInfinity && ellipticCurvePointFp.isInfinity) {
                return true;
            }

            // Otherwise its member-wise comparison

            if (returnObj.z === null && ellipticCurvePointFp.z !== null) {
                return false;
            }

            if (returnObj.z !== null && ellipticCurvePointFp.z === null) {
                return false;
            }

            if (returnObj.z === null) {
                return cryptoMath.compareDigits(returnObj.x, ellipticCurvePointFp.x) === 0 &&
                    cryptoMath.compareDigits(returnObj.y, ellipticCurvePointFp.y) === 0 &&
                    returnObj.isInMontgomeryForm === ellipticCurvePointFp.isInMontgomeryForm;
            }

            return cryptoMath.compareDigits(returnObj.x, ellipticCurvePointFp.x) === 0 &&
                cryptoMath.compareDigits(returnObj.y, ellipticCurvePointFp.y) === 0 &&
                cryptoMath.compareDigits(returnObj.z, ellipticCurvePointFp.z) === 0 &&
                returnObj.isInMontgomeryForm === ellipticCurvePointFp.isInMontgomeryForm;
        }

        function copyTo(/*@type(EllipticCurvePointFp)*/ source, /*@type(EllipticCurvePointFp)*/ destination) {
            /// <param name="source" type="EllipticCurvePointFp"/>
            /// <param name="destination" type="EllipticCurvePointFp"/>

            destination.curve = source.curve;
            destination.x = source.x.slice();
            destination.y = source.y.slice();

            if (source.z !== null) {
                destination.z = source.z.slice();
            } else {
                destination.z = null;
            }

            // tslint:disable-next-line: no-unused-expression
            setterSupport || (destination.isAffine = source.isAffine);
            destination.isInMontgomeryForm = source.isInMontgomeryForm;
            destination.isInfinity = source.isInfinity;

            if (!destination.equals(source)) {
                throw new Error("Instances should be equal.");
            }

        }

        function clone() {

            var clonePoint = EllipticCurvePointFp(
                returnObj.curve,
                returnObj.isInfinity,
                createArray(returnObj.x),
                createArray(returnObj.y),
                returnObj.z ? createArray(returnObj.z) : null,
                returnObj.isInMontgomeryForm);

            // tslint:disable-next-line: no-unused-expression
            returnObj.ta && (clonePoint.ta = createArray(returnObj.ta));
            // tslint:disable-next-line: no-unused-expression
            returnObj.tb && (clonePoint.tb = createArray(returnObj.tb));

            return clonePoint;
        }

        returnObj = /*@static_cast(EllipticCurvePointFp)*/ {
            equals: function(ellipticCurvePointFp) {
                return equals(ellipticCurvePointFp);
            },
            copy: function(destination) {
                copyTo(this, destination);
                return;
            },
            clone: function() {
                return clone();
            }
        };

        createProperty(returnObj, "curve", curve, function() { return curve; }, function(val) { curve = val; });

        createProperty(returnObj, "x", x, function() { return x; }, function(val) { x = val; });
        createProperty(returnObj, "y", y, function() { return y; }, function(val) { y = val; });
        createProperty(returnObj, "z", z, function() { return z; }, function(val) { z = val; });

        createProperty(returnObj, "isInMontgomeryForm", isInMontgomeryForm,
            function() { return isInMontgomeryForm; }, function(val) { isInMontgomeryForm = val; });
        createProperty(returnObj, "isInfinity", isInfinity,
            function() { return isInfinity; }, function(val) { isInfinity = val; });
        createProperty(returnObj, "isAffine", z === null, function() { return z === null; });

        return returnObj;
    };

    var EllipticCurveOperatorFp = function(curve) {
        /// <param name="curve" type="EllipticCurveFp"/>

        // Store a reference to the curve.
        // tslint:disable-next-line: variable-name
        var m_curve = curve;

        var tedCurve = curve.type === 1;

        var fieldElementWidth = curve.p.length;

        var montgomeryMultiplier = cryptoMath.MontgomeryMultiplier(curve.p);

        // Pre-compute and store the montgomeryized form of A, and set our
        // zero flag to determine whether or not we should use implementations
        // optimized for A = 0.
        var montgomerizedA = curve.a.slice();
        montgomeryMultiplier.convertToMontgomeryForm(montgomerizedA);

        var aequalsZero = cryptoMath.isZero(curve.a);

        var one = cryptoMath.One;

        var onemontgomery = createArray(fieldElementWidth);
        onemontgomery[0] = 1;
        montgomeryMultiplier.convertToMontgomeryForm(onemontgomery);

        var group = cryptoMath.IntegerGroup(cryptoMath.digitsToBytes(montgomeryMultiplier.m), true);

        // Setup temp storage.
        var temp0 = createArray(fieldElementWidth);
        var temp1 = createArray(fieldElementWidth);
        var temp2 = createArray(fieldElementWidth);
        var temp3 = createArray(fieldElementWidth);
        var temp4 = createArray(fieldElementWidth);
        var temp5 = createArray(fieldElementWidth);
        var temp6 = createArray(fieldElementWidth);
        var temp7 = createArray(fieldElementWidth);
        var swap0 = createArray(fieldElementWidth);

        // Some additional temp storage used in point conversion routines.
        var conversionTemp0 = createArray(fieldElementWidth);
        var conversionTemp1 = createArray(fieldElementWidth);
        var conversionTemp2 = createArray(fieldElementWidth);

        function modSub(left, right, result) {
            var resultElement = group.createElementFromInteger(0);
            resultElement.m_digits = result;
            group.subtract(
                group.createElementFromDigits(left),
                group.createElementFromDigits(right),
                resultElement);
        }

        function modAdd(left, right, result) {
            var resultElement = group.createElementFromInteger(0);
            resultElement.m_digits = result;
            group.add(
                group.createElementFromDigits(left),
                group.createElementFromDigits(right),
                resultElement);
        }

        // tslint:disable-next-line: variable-name
        function modInv(number, result) {
            cryptoMath.modInv(number, m_curve.p, result);
        }

        function modDivByTwo( /*@type(Digits)*/ dividend,  /*@type(Digits)*/ result) {

            var s = dividend.length;

            var modulus = curve.p;

            // If dividend is odd, add modulus
            if ((dividend[0] & 0x1) === 0x1) {
                var carry = 0;

                for (var i = 0; i < s; i += 1) {
                    carry += dividend[i] + modulus[i];
                    result[i] = carry & cryptoMath.DIGIT_MASK;
                    carry = carry >>> cryptoMath.DIGIT_BITS;
                }

                // Put carry bit into position for masking in
                carry = carry << cryptoMath.DIGIT_BITS - 1;

                // Bit shift
                cryptoMath.shiftRight(result, result);

                // Mask in the carry bit
                result[s - 1] |= carry;
            } else {
                // Shift directly into result
                cryptoMath.shiftRight(dividend, result);
            }

        }

        function montgomeryMultiply(left, right, result) {
            montgomeryMultiplier.montgomeryMultiply(
                left,
                right,
                result);
        }

        function montgomerySquare(left, result) {
            montgomeryMultiplier.montgomeryMultiply(
                left,
                left,
                result);
        }

        function correctInversion(digits) {
            /// <param name="digits" type="Digits"/>
            var results = createArray(digits.length);
            montgomeryMultiply(digits, montgomeryMultiplier.rCubedModm, results);
            for (var i = 0; i < results.length; i += 1) {
                digits[i] = results[i];
            }
        }

        function doubleAequalsNeg3(point, outputPoint) {
            /// <param name="point" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            // If point = infinity then outputPoint := infinity.
            if (point.isInfinity) {
                outputPoint.isInfinity = true;
                return;
            }

            // t1 = z^2
            montgomerySquare(point.z, temp1);

            // t4 = zy
            montgomeryMultiply(point.z, point.y, temp4);

            // t2 = x + z^2
            // t2 = x + t1
            modAdd(point.x, temp1, temp2);

            // t1 = x - z^2
            // t1 = x - t1
            modSub(point.x, temp1, temp1);

            // Zfinal = zy
            outputPoint.z = temp4.slice();

            // t3 = (x + z^2)(x - z^2)
            montgomeryMultiply(temp1, temp2, temp3);

            // t2 = (x + z^2)(x - z^2)/2
            modDivByTwo(temp3, temp2);

            // t1 = alpha = 3(x + z^2)(x - z^2)/2
            modAdd(temp3, temp2, temp1);

            // t2 = y^2
            montgomerySquare(point.y, temp2);

            // t4 = alpha^2
            montgomerySquare(temp1, temp4);

            // t3 = beta = xy^2
            montgomeryMultiply(point.x, temp2, temp3);

            // t4 = alpha^2-beta
            modSub(temp4, temp3, temp4);

            // Xfinal = alpha^2-2beta
            modSub(temp4, temp3, outputPoint.x);

            // t4 = beta-Xfinal
            modSub(temp3, outputPoint.x, temp4);

            // t3 = y^4
            montgomerySquare(temp2, temp3);

            // t3 = y^4
            montgomeryMultiply(temp1, temp4, temp2);

            // Yfinal = alpha.(beta-Xfinal)-y^4
            modSub(temp2, temp3, outputPoint.y);

            // Finalize the flags on the output point.
            outputPoint.isInfinity = false;
            outputPoint.isInMontgomeryForm = true;
        }

        function doubleAequals0(point, outputPoint) {
            /// <param name="point" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            // If point = infinity then outputPoint := infinity.
            if (point.isInfinity) {
                outputPoint.isInfinity = true;
                return;
            }

            // 't3:=Y1^2;'
            montgomerySquare(point.y, temp3);

            // 't4:=X1^2;'
            montgomerySquare(point.x, temp4);

            // 't4:=3*t4;'
            modAdd(temp4, temp4, temp0);
            modAdd(temp0, temp4, temp4);

            // 't5:=X1*t3;'
            montgomeryMultiply(point.x, temp3, temp5);

            // 't0:=t3^2;'
            montgomerySquare(temp3, temp0);

            // 't1:=t4/2;'
            modDivByTwo(temp4, temp1);

            // 't3:=t1^2;'
            montgomerySquare(temp1, temp3);

            // 'Z_out:=Y1*Z1;'
            montgomeryMultiply(point.y, point.z, swap0);
            for (var i = 0; i < swap0.length; i += 1) {
                outputPoint.z[i] = swap0[i];
            }

            // 'X_out:=t3-2*t5;'
            modSub(temp3, temp5, outputPoint.x);
            modSub(outputPoint.x, temp5, outputPoint.x);

            // 't4:=t5-X_out;'
            modSub(temp5, outputPoint.x, temp4);

            // 't2:=t1*t4;'
            montgomeryMultiply(temp1, temp4, temp2);

            // 'Y_out:=t2-t0;'
            modSub(temp2, temp0, outputPoint.y);

            // Finalize the flags on the output point.
            outputPoint.isInfinity = false;
            outputPoint.isInMontgomeryForm = true;
        }

        // Given a povar P on an elliptic curve, return a table of
        // size 2^(w-2) filled with pre-computed values for
        // P, 3P, 5P, ... Etc.
        function generatePrecomputationTable(w, generatorPoint) {
            /// <summary>Given a point P on an elliptic curve, return a table of
            /// size 2^(w-2) filled with pre-computed values for
            /// P, 3P, 5P, ... Etc.</summary>
            /// <param name="w" type="Array">Window size</param>
            /// <param name="generatorPoint" type="EllipticCurvePointFp"></param>
            /// <returns type="Array">Precomputation table</returns>

            var validationPoint = generatorPoint.clone();
            convertToStandardForm(validationPoint);
            if (!validatePoint(validationPoint)) {
                throw new Error("Invalid Parameter");
            }

            // Create a Jacobian clone
            var pointJac = generatorPoint.clone();
            convertToJacobianForm(pointJac);

            var tablePos = [generatorPoint.clone()];

            // Q := P;
            var qJac = pointJac.clone();

            // Px2 = 2 * P
            var px2 = pointJac.clone();
            double(pointJac, px2);
            convertToAffineForm(px2);

            var qAff;

            for (var i = 1; i < Math.pow(2, w - 2); i++) {

                //Q := Q+P2;
                mixedAdd(qJac, px2, qJac);

                qAff = qJac.clone();
                convertToAffineForm(qAff);

                tablePos[i] = qAff;
            }

            return tablePos;
        }

        function double(point, outputPoint) {
            /// <param name="point" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            if (typeof point === "undefined") {
                throw new Error("point undefined");
            }
            if (typeof outputPoint === "undefined") {
                throw new Error("outputPoint undefined");
            }

            //// if (!point.curve.equals(outputPoint.curve)) {
            ////    throw new Error("point and outputPoint must be from the same curve object.");
            //// }

            if (point.isAffine) {
                throw new Error("Given point was in Affine form. Use convertToJacobian() first.");
            }

            if (!point.isInMontgomeryForm) {
                throw new Error("Given point must be in Montgomery form. Use montgomeryize() first.");
            }
            // Currently we support only two curve types, those with A=-3, and
            // those with A=0. In the future we will implement general support.
            // For now we switch here, assuming that the curve was validated in
            // the constructor.
            if (aequalsZero) {
                doubleAequals0(point, outputPoint);
            } else {
                doubleAequalsNeg3(point, outputPoint);
            }

        }

        function mixedDoubleAdd(jacobianPoint, affinePoint, outputPoint) {
            /// <param name="jacobianPoint" type="EllipticCurvePointFp"/>
            /// <param name="affinePoint" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            if (jacobianPoint.isInfinity) {
                affinePoint.copy(outputPoint);
                this.convertToJacobianForm(outputPoint);
                return;
            }

            if (affinePoint.isInfinity) {
                jacobianPoint.copy(outputPoint);
                return;
            }

            // Ok then we do the full double and add.

            // Note: in pseudo-code the uppercase X,Y,Z is Jacobian point, lower
            // case x, y, z is Affine point.

            // 't5:=Z1^ 2;'
            montgomerySquare(jacobianPoint.z, temp5);

            // 't6:=Z1*t5;'
            montgomeryMultiply(jacobianPoint.z, temp5, temp6);

            // 't4:=x2*t5;'
            montgomeryMultiply(affinePoint.x, temp5, temp4);

            // 't5:=y2*t6;'
            montgomeryMultiply(affinePoint.y, temp6, temp5);

            // 't1:=t4-X1;'
            modSub(temp4, jacobianPoint.x, temp1);

            // 't2:=t5-Y1;'
            modSub(temp5, jacobianPoint.y, temp2);

            //if t1 eq 0 then
            if (cryptoMath.isZero(temp1)) {
                // if t2 eq 0 then
                if (cryptoMath.isZero(temp2)) {
                    //  X2,Y2,Z2 := DBL(X1,Y1,Z1,prime,rr,m,RR);
                    // return mADD(X2,Y2,Z2,x2,y2,prime,rr,m,RR);
                    double(jacobianPoint, outputPoint);
                    mixedAdd(outputPoint, affinePoint, outputPoint);
                    return;
                } else {
                    // return X1,Y1,Z1;Z
                    outputPoint.x = jacobianPoint.x.slice(0);
                    outputPoint.y = jacobianPoint.y.slice(0);
                    outputPoint.z = jacobianPoint.z.slice(0);
                    return;
                }
            }

            // 't4:=t2^2;'
            montgomerySquare(temp2, temp4);

            // 't6:=t1^2;'
            montgomerySquare(temp1, temp6);

            // 't5:=t6*X1;'
            montgomeryMultiply(temp6, jacobianPoint.x, temp5);

            // 't0:=t1*t6;'
            montgomeryMultiply(temp1, temp6, temp0);

            // 't3:=t4-2*t5;'
            modSub(temp4, temp5, temp3);
            modSub(temp3, temp5, temp3);

            // 't4:=Z1*t1;'
            montgomeryMultiply(jacobianPoint.z, temp1, temp4);

            // 't3:=t3-t5;'
            modSub(temp3, temp5, temp3);

            // 't6:=t0*Y1;'
            montgomeryMultiply(temp0, jacobianPoint.y, temp6);

            // 't3:=t3-t0;'
            modSub(temp3, temp0, temp3);

            //if t3 eq 0 then
            //    return 0,1,0;
            //end if;
            //var temp3isZero = cryptoMath.isZero(temp3);

            // for (var i = 0; i < temp3.length; i++) {
            //     if (temp3[i] !== 0) {
            //         temp3isZero = false;
            //         break;
            //     }
            // }

            if (cryptoMath.isZero(temp3)) {
                for (i = 0; i < outputPoint.x.length; i++) {
                    outputPoint.x[i] = 0;
                    outputPoint.y[i] = 0;
                    outputPoint.z[i] = 0;
                }
                outputPoint.y[0] = 1;
                return;
            }

            // 't1:=2*t6;'
            modAdd(temp6, temp6, temp1);

            // 'Zout:=t4*t3;'
            montgomeryMultiply(temp4, temp3, outputPoint.z);

            // 't4:=t2*t3;'
            montgomeryMultiply(temp2, temp3, temp4);

            // 't0:=t3^2;'
            montgomerySquare(temp3, temp0);

            // 't1:=t1+t4;'
            modAdd(temp1, temp4, temp1);

            // 't4:=t0*t5;'
            montgomeryMultiply(temp0, temp5, temp4);

            // 't7:=t1^2;'
            montgomerySquare(temp1, temp7);

            // 't4:=t0*t5;'
            montgomeryMultiply(temp0, temp3, temp5);

            // 'Xout:=t7-2*t4;'
            modSub(temp7, temp4, outputPoint.x);
            modSub(outputPoint.x, temp4, outputPoint.x);

            // 'Xout:=Xout-t5;'
            modSub(outputPoint.x, temp5, outputPoint.x);

            // 't3:=Xout-t4;'
            modSub(outputPoint.x, temp4, temp3);

            // 't0:=t5*t6;'
            montgomeryMultiply(temp5, temp6, temp0);

            // 't4:=t1*t3;'
            montgomeryMultiply(temp1, temp3, temp4);

            // 'Yout:=t4-t0;'
            modSub(temp4, temp0, outputPoint.y);

            outputPoint.isInfinity = false;
            outputPoint.isInMontgomeryForm = true;

        }

        function mixedAdd(jacobianPoint, affinePoint, outputPoint) {
            /// <param name="jacobianPoint" type="EllipticCurvePointFp"/>
            /// <param name="affinePoint" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            if (jacobianPoint === null) {
                throw new Error("jacobianPoint");
            }

            if (affinePoint === null) {
                throw new Error("affinePoint");
            }

            if (outputPoint === null) {
                throw new Error("outputPoint");
            }

            if (jacobianPoint.curve !== affinePoint.curve ||
                jacobianPoint.curve !== outputPoint.curve) {
                throw new Error("All points must be from the same curve object.");
            }

            if (jacobianPoint.isAffine) {
                throw new Error(
                    "Given jacobianPoint was in Affine form. Use ConvertToJacobian()\
                     before calling DoubleJacobianAddAffinePoints().");
            }

            if (!affinePoint.isAffine) {
                throw new Error(
                    "Given affinePoint was in Jacobian form. Use ConvertToAffine() before \
                     calling DoubleJacobianAddAffinePoints().");
            }

            if (outputPoint.isAffine) {
                throw new Error(
                    "Given jacobianPoint was in Jacobian form. Use ConvertToJacobian() before \
                     calling DoubleJacobianAddAffinePoints().");
            }

            if (!jacobianPoint.isInMontgomeryForm) {
                throw new Error("Jacobian point must be in Montgomery form");
            }

            if (!affinePoint.isInMontgomeryForm) {
                throw new Error("Affine point must be in Montgomery form");
            }

            if (jacobianPoint.isInfinity) {
                affinePoint.copy(outputPoint);
                this.convertToJacobianForm(outputPoint);
                return;
            }

            if (affinePoint.isInfinity) {
                jacobianPoint.copy(outputPoint);
                return;
            }

            // Ok then we do the full double and add.

            // Note: in pseudo-code the uppercase X1,Y1,Z1 is Jacobian point,
            // lower case x2, y2, z2 is Affine point.

            //if (X1 eq 0) and (Y1 eq 1) and (Z1 eq 0) then
            //    z2 := ToMontgomery(1,prime,rr,m,RR);
            //    return x2,y2;
            //end if;
            //if (x2 eq 0) and (y2 eq 1) then
            //    return X1,Y1,Z1;
            //end if;

            // 't1 := Z1^2;'.
            montgomerySquare(jacobianPoint.z, temp1);

            // 't2 := t1 * Z1;'
            montgomeryMultiply(temp1, jacobianPoint.z, temp2);

            // 't3 := t1 * x2;'
            montgomeryMultiply(temp1, affinePoint.x, temp3);

            // 't4 := t2 * y2;'
            montgomeryMultiply(temp2, affinePoint.y, temp4);

            // 't1 := t3 - X1;'
            modSub(temp3, jacobianPoint.x, temp1);

            // 't2 := t4 - Y1;'
            modSub(temp4, jacobianPoint.y, temp2);

            // If t1 != 0 then
            var i;
            for (i = 0; i < temp1.length; i += 1) {
                if (temp1[i] !== 0) {

                    // 'Zout := Z1 * t1;'
                    montgomeryMultiply(jacobianPoint.z, temp1, temp0);
                    for (var j = 0; j < fieldElementWidth; j += 1) {
                        outputPoint.z[j] = temp0[j];
                    }

                    // 't3 := t1^2;'
                    montgomerySquare(temp1, temp3);

                    // 't4 := t3 * t1;'
                    montgomeryMultiply(temp3, temp1, temp4);

                    // 't5 := t3 * X1;'
                    montgomeryMultiply(temp3, jacobianPoint.x, temp5);

                    // 't1 := 2 * t5;'
                    modAdd(temp5, temp5, temp1);

                    // 'Xout := t2^2;'
                    montgomerySquare(temp2, outputPoint.x);

                    // 'Xout := Xout - t1;'
                    modSub(outputPoint.x, temp1, outputPoint.x);

                    // 'Xout := Xout - t4;'
                    modSub(outputPoint.x, temp4, outputPoint.x);

                    // 't3 := t5 - Xout;'
                    modSub(temp5, outputPoint.x, temp3);

                    // 't5 := t3*t2;'
                    montgomeryMultiply(temp2, temp3, temp5);

                    // 't6 := t4*Y1;'
                    montgomeryMultiply(jacobianPoint.y, temp4, temp6);

                    // 'Yout := t5-t6;'
                    modSub(temp5, temp6, outputPoint.y);

                    outputPoint.isInfinity = false;
                    outputPoint.isInMontgomeryForm = true;

                    return;
                }
            }

            // Else if T2 != 0 then
            for (i = 0; i < temp2.length; i += 1) {
                if (temp2[i] !== 0) {
                    //         Return infinity
                    outputPoint.isInfinity = true;
                    outputPoint.isInMontgomeryForm = true;
                    return;
                }
            }
            // Else use DBL routine to return 2(x2, y2, 1)
            affinePoint.copy(outputPoint);
            this.convertToJacobianForm(outputPoint);
            this.double(outputPoint, outputPoint);
            outputPoint.isInMontgomeryForm = true;

        }

        function scalarMultiply(k, point, outputPoint, multiplyBy4) {
            /// <param name="k" type="Digits"/>
            /// <param name="point" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            // Special case for the point at infinity or k == 0
            if (point.isInfinity || cryptoMath.isZero(k)) {
                outputPoint.isInfinity = true;
                return;
            }

            // Runtime check for 1 <= k < order to ensure we don't get hit by
            // subgroup attacks. Since k is a FixedWidth it is a positive integer
            // and we already checked for zero above. So it must be >= 1 already.
            if (cryptoMath.compareDigits(k, curve.order) >= 0) {
                throw new Error("The scalar k must be in the range 1 <= k < order.");
            }

            // copy k so we can modify it without modifying the passed in array.
            k = k.slice();

            if (point.curve.type === 1 /* TED */) {

                var pointIsEP = typeof point.ta !== "undefined";

                if (!pointIsEP) {
                    convertToExtendedProjective(point);
                }

                scalarMultiplyTed(k, point, outputPoint, multiplyBy4);

                // Convert the points back to standard if they arrived that way.
                if (!pointIsEP) {
                    normalizeTed(point);
                }

            } else {

                var pointIsMF = point.isInMontgomeryForm,
                    outputIsMF = outputPoint.isInMontgomeryForm,
                    outputIsAffine = outputPoint.isAffine;

                // Convert parameters to Montgomery form if not already.
                if (!pointIsMF) {
                    convertToMontgomeryForm(point);
                }

                if (!outputIsMF) {
                    convertToMontgomeryForm(outputPoint);
                }

                scalarMultiplyW(k, point, outputPoint);

                // outputPoint returns as Jacobian - convert back to original state.
                if (outputIsAffine) {
                    convertToAffineForm(outputPoint);
                }

                // Convert the points back to standard if they arrived that way.
                if (!pointIsMF) {
                    convertToStandardForm(point);
                }

                if (!outputIsMF) {
                    convertToStandardForm(outputPoint);
                }
            }

            return;

        }

        function scalarMultiplyW(k, point, outputPoint) {
            /// <param name="k" type="Digits"/>
            /// <param name="point" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            // The point should be in Montgomery form.
            var validationPoint = point.clone();
            convertToStandardForm(validationPoint);

            if (!validatePoint(validationPoint)) {
                throw new Error("Invalid Parameters.");
            }

            var odd = k[0] & 1,
                tempk = [];

            // If (odd) then k = temp else k = k
            modSub(point.curve.order, k, tempk);
            for (i = 0; i < k.length; i++) {
                k[i] = odd - 1 & (k[i] ^ tempk[i]) ^ k[i];
            }

            // Change w based on the size of the digits,
            // 5 is good for 256 bits, use 6 for bigger sizes.
            var w = fieldElementWidth <= 8 ? 5 : 6;
            var m = point.curve.p.length * cryptoMath.DIGIT_BITS;
            var t = Math.ceil(m / (w - 1));

            var kDigits = cryptoMath.fixedWindowRecode(k, w, t);

            var Tm = generatePrecomputationTable(w, point);

            var position =
                Math.floor(Math.abs(kDigits[t]) - 1) / 2;

            var Q = Tm[position].clone();
            convertToJacobianForm(Q);

            for (var i = t - 1; i >= 0; i--) {

                for (var j = 0; j < w - 2; j++) {
                    double(Q, Q);
                }

                position = Math.floor((Math.abs(kDigits[i]) - 1) / 2);

                var L = tableLookupW(Tm, position);

                // if (kDigits[i] < 0) negate(L) - constant-time
                //modSub(L.curve.p, L.y, [tempk, L.y][kDigits[i] >>> 31]);
                modSub(L.curve.p, L.y, tempk);
                var mask = -(kDigits[i] >>> 31);
                for (var n = 0; n < L.y.length; n++) {
                    L.y[n] = (L.y[n] & ~mask) | (tempk[n] & mask);
                }

                mixedDoubleAdd(Q, L, Q);

            }

            // if k is even, negate Q
            modSub(point.curve.p, Q.y, tempk);
            for (i = 0; i < Q.y.length; i++) {
                Q.y[i] = odd - 1 & (Q.y[i] ^ tempk[i]) ^ Q.y[i];
            }

            Q.copy(outputPoint);

            return;

        }

        function tableLookupW(table, index) {

            var mask,
                L;

            for (var i = 0; i < table.length; i++) {
                mask = +(i === index);
                L = [L, table[i].clone()][mask];
            }

            return L;
        }

        function tableLookupW0(table, index) {

            var pos = (index + 1) % table.length;

            for (var i = 0; i < table.length; i++) {
                var L = table[pos].clone();
                pos = (pos + 1) % table.length;
            }

            return L;
        }

        function negate(point, outputPoint) {
            /// <param name="point" type="EllipticCurvePointFp">Input point to negate.</param>
            /// <param name="outputPoint" type="EllipticCurvePointFp">(x, p - y).</param>

            if (point !== outputPoint) {
                point.copy(outputPoint);
            }
            modSub(point.curve.p, point.y, outputPoint.y);
        }

        function convertToMontgomeryForm(point) {
            /// <param name="point" type="EllipticCurvePointFp"/>

            if (point.isInMontgomeryForm) {
                throw new Error("The given point is already in Montgomery form.");
            }

            if (!point.isInfinity) {
                montgomeryMultiplier.convertToMontgomeryForm(point.x);
                montgomeryMultiplier.convertToMontgomeryForm(point.y);

                if (point.z !== null) {
                    montgomeryMultiplier.convertToMontgomeryForm(point.z);
                }

                if (typeof point.ta !== "undefined") {
                    montgomeryMultiplier.convertToMontgomeryForm(point.ta);
                    montgomeryMultiplier.convertToMontgomeryForm(point.tb);
                }
            }

            point.isInMontgomeryForm = true;
        }

        function convertToStandardForm(point) {
            /// <param name="point" type="EllipticCurvePointFp"/>

            if (!point.isInMontgomeryForm) {
                throw new Error("The given point is not in montgomery form.");
            }

            if (!point.isInfinity) {
                montgomeryMultiplier.convertToStandardForm(point.x);
                montgomeryMultiplier.convertToStandardForm(point.y);
                if (point.z !== null) {
                    montgomeryMultiplier.convertToStandardForm(point.z);
                }
                if (typeof point.ta !== "undefined") {
                    montgomeryMultiplier.convertToStandardForm(point.ta);
                    montgomeryMultiplier.convertToStandardForm(point.tb);
                }
            }

            point.isInMontgomeryForm = false;

        }

        function convertToAffineForm(point) {
            /// <param name="point" type="EllipticCurvePointFp"/>

            if (point.isInfinity) {
                point.z = null;
                // tslint:disable-next-line: no-unused-expression
                setterSupport || (point.isAffine = true);
                return;
            }

            // DETERMINE 1/Z IN MONTGOMERY FORM --------------------------------

            // Call out to the basic inversion function, not the one in this class.
            cryptoMath.modInv(point.z, curve.p, conversionTemp2, true);

            if (point.isInMontgomeryForm) {
                montgomeryMultiply(conversionTemp2, montgomeryMultiplier.rCubedModm, conversionTemp1);
                var swap = conversionTemp2;
                conversionTemp2 = conversionTemp1;
                conversionTemp1 = swap;
            }

            // CONVERT TO AFFINE COORDS ----------------------------------------

            // 'temp0 <- 1/z^2'
            montgomerySquare(conversionTemp2, conversionTemp0);

            // Compute point.x = x / z^2 mod p
            // NOTE: We cannot output directly to the X digit array since it is
            // used for input to the multiplication routine, so we output to temp1
            // and copy.
            montgomeryMultiply(point.x, conversionTemp0, conversionTemp1);
            for (var i = 0; i < fieldElementWidth; i += 1) {
                point.x[i] = conversionTemp1[i];
            }

            // Compute point.y = y / z^3 mod p
            // temp1 <- y * 1/z^2.
            montgomeryMultiply(point.y, conversionTemp0, conversionTemp1);
            // 'y <- temp1 * temp2 (which == 1/z)'
            montgomeryMultiply(conversionTemp1, conversionTemp2, point.y);

            // Finally, point.z = z / z mod p = 1
            // We use z = NULL for this case to make detecting Jacobian form
            // faster (otherwise we would have to scan the entire Z digit array).
            point.z = null;

            delete point.ta;
            delete point.tb;

            // tslint:disable-next-line: no-unused-expression
            setterSupport || (point.isAffine = true);
        }

        function convertToJacobianForm(point) {
            /// <param name="point" type="EllipticCurvePointFp"/>

            if (!point.isAffine) {
                throw new Error("The given point is not in Affine form.");
            }

            // tslint:disable-next-line: no-unused-expression
            setterSupport || (point.isAffine = false);

            var clonedDigits,
                i,
                zOne = point.isInMontgomeryForm ? onemontgomery : one;

            clonedDigits = createArray(zOne.length);
            for (i = 0; i < zOne.length; i += 1) {
                clonedDigits[i] = zOne[i];
            }

            point.z = clonedDigits;

            return;
        }

        function validatePoint(point) {
            /// <summary>
            /// Point validation
            //  Check if point P=(x,y) lies on the curve and if x,y are in [0, p-1]
            /// </summary>

            if (point.isInfinity) {
                return false;
            }

            // Does P lie on the curve?
            cryptoMath.modMul(point.y, point.y, point.curve.p, temp1);

            cryptoMath.modMul(point.x, point.x, point.curve.p, temp2);
            cryptoMath.modMul(point.x, temp2, point.curve.p, temp3);
            modAdd(temp3, point.curve.b, temp2);
            cryptoMath.modMul(point.x, point.curve.a, point.curve.p, temp3);
            modAdd(temp2, temp3, temp2);
            modSub(temp1, temp2, temp1);

            if (cryptoMath.isZero(temp1) === false) {
                return false;
            }

            return true;
        }

        /// Ted functions

        function validatePointTed(point) {

            if (point.ta) {
                point = point.clone();
                normalizeTed(point);
            }

            // Does P lie on the curve?
            cryptoMath.modMul(point.y, point.y, point.curve.p, temp3);
            cryptoMath.modMul(point.x, point.x, point.curve.p, temp2);

            cryptoMath.add(temp2, temp3, temp1);
            cryptoMath.reduce(temp4, point.curve.p, temp4);

            cryptoMath.modMul(temp2, temp3, point.curve.p, temp4);
            cryptoMath.modMul(point.curve.d, temp4, point.curve.p, temp3);

            cryptoMath.add(temp3, [1], temp2);
            cryptoMath.reduce(temp2, point.curve.p, temp2);

            cryptoMath.subtract(temp1, temp2, temp1);

            if (cryptoMath.isZero(temp1) === false) {
                cryptoMath.reduce(temp1, point.curve.p, temp1);
                if (cryptoMath.isZero(temp1) === false) {
                    return false;
                }
            }

            return true;
        }

        function generatePrecomputationTableTed(npoints, point) {

            // Precomputation function, points are stored using representation (X,Y,Z,dT)
            // Twisted Edwards a=1 curve

            var Q = point.clone(),
                P2 = Q.clone(),
                T = [];

            // Generating P2 = 2(X1,Y1,Z1,T1a,T1b) -> (XP2,YP2,ZP2,d*TP2) and T[0] = P = (X1,Y1,Z1,T1a,T1b)
            T[0] = convert_R1_to_R2(point);
            doubleTed(Q, Q);
            P2 = convert_R1_to_R2(Q);
            Q = point.clone();

            for (var i = 1; i < npoints; i++) {
                // T[i] = 2P+T[i-1] = (2*i+1)P = (XP2,Y2P,ZP2,d*TP2) + (X_(2*i-1), Y_(2*i-1), Z_(2*i-1), Ta_(2*i-1),
                // Tb_(2 * i - 1)) = (X_(2 * i + 1), Y_(2 * i + 1), Z_(2 * i + 1), d * T_(2 * i + 1))
                addTedExtended(P2, Q, Q);
                T[i] = convert_R1_to_R2(Q);
            }

            return T;
        }

        function convertToExtendedProjective(affinePoint) {
            affinePoint.ta = affinePoint.x.slice();
            affinePoint.tb = affinePoint.y.slice();
            affinePoint.z = [1];
        }

        function scalarMultiplyTed(k, point, outputPoint, multiplyBy4) {

            if (!validatePointTed(point)) {
                throw new Error("Invalid Parameter");
            }

            var rbits = point.curve.rbits;
            multiplyBy4 = typeof multiplyBy4 === "undefined" ? true : multiplyBy4;

            var w = fieldElementWidth <= 8 ? 5 : 6;

            var t = Math.floor((rbits + (w - 2)) / (w - 1));
            var i, j;

            // copy k so we can modify it without modifying the passed in array.
            k = k.slice();

            var T = point.clone();

            convertToExtendedProjective(T);

            if (multiplyBy4) {
                doubleTed(T, T);
                doubleTed(T, T);
            }

            var precomputationTable = generatePrecomputationTableTed(1 << w - 2, T);

            var odd = k[0] & 1,
                tempk = [],
                kisNeg;

            // If (odd) then k = temp else k = k
            modSub(point.curve.order, k, tempk);
            for (i = 0; i < k.length; i++) {
                k[i] = odd - 1 & (k[i] ^ tempk[i]) ^ k[i];
            }

            var kDigits = cryptoMath.fixedWindowRecode(k, w, t);

            var position =
                Math.floor(Math.abs(kDigits[t]) - 1) / 2;

            var R = precomputationTable[position];

            T.x = R.x.slice();
            T.y = R.y.slice();
            T.z = R.z.slice();

            for (i = t - 1; i >= 0; i--) {

                for (j = 0; j < w - 1; j++) {
                    doubleTed(T, T);
                }

                position = Math.floor((Math.abs(kDigits[i]) - 1) / 2);

                var L = tableLookupTed(precomputationTable, position);

                // subtract if k is negative - constant time
                // modSub(point.curve.p, L.x, [tempk, L.x][kisNeg]);
                // modSub(point.curve.p, L.td, [tempk, L.td][kisNeg]);

                var mask = -(kDigits[i] >>> 31);

                modSub(point.curve.p, L.x, tempk);
                for (var m = 0; m < L.x.length; m++) {
                    L.x[m] = (L.x[m] & ~mask) | (tempk[m] & mask);
                }

                modSub(point.curve.p, L.td, tempk);
                for (m = 0; m < L.td.length; m++) {
                    L.td[m] = (L.td[m] & ~mask) | (tempk[m] & mask);
                }

                addTedExtended(L, T, T);
            }

            // If (odd) then T.x = temp else T.x = T.x
            modSub(point.curve.p, T.x, tempk);
            for (i = 0; i < T.x.length; i++) {
                T.x[i] = odd - 1 & (T.x[i] ^ tempk[i]) ^ T.x[i];
            }

            normalizeTed(T);

            outputPoint.x = T.x.slice();
            outputPoint.y = T.y.slice();

            return;

        }

        function tableLookupTed(table, index) {

            var pos = (index + 1) % table.length;

            for (var i = 0; i < table.length; i++) {
                var L = {
                    x: table[pos].x.slice(),
                    y: table[pos].y.slice(),
                    z: table[pos].z.slice(),
                    td: table[pos].td.slice()
                };
                pos = (pos + 1) % table.length;
            }

            return L;
        }

        function normalizeTed(point) {

            cryptoMath.modInv(point.z, curve.p, conversionTemp2, true);

            cryptoMath.modMul(point.x, conversionTemp2, curve.p, point.x);

            cryptoMath.modMul(point.y, conversionTemp2, curve.p, point.y);

            delete point.ta;
            delete point.tb;

            point.z = null;

            return;
        }

        function doubleTed(point, outputPoint) {

            if (typeof point.ta === "undefined") {
                throw new Error("Point should be in Extended Projective form.");
            }

            // t0 = x1^2
            cryptoMath.modMul(point.x, point.x, point.curve.p, temp0);

            // t1 = y1^2
            cryptoMath.modMul(point.y, point.y, point.curve.p, temp1);

            // Ta = z1^2
            cryptoMath.modMul(point.z, point.z, point.curve.p, point.ta);
            // (new) Tbfinal = Y1^2-X1^2
            modSub(temp1, temp0, outputPoint.tb);
            //(new) t0 = X1^2+Y1^2
            modAdd(temp0, temp1, temp0);

            //(ok) Ta = 2z1^2
            modAdd(point.ta, point.ta, point.ta);

            // (ok) y = 2y1
            modAdd(point.y, point.y, point.y);

            // (new) t1 = 2z1^2-(X1^2+Y1^2)
            modSub(point.ta, temp0, temp1);

            // Tafinal = 2x1y1
            cryptoMath.modMul(point.x, point.y, point.curve.p, outputPoint.ta);

            // Yfinal = (x1^2+y1^2)(y1^2-x1^2)
            cryptoMath.modMul(temp0, outputPoint.tb, point.curve.p, outputPoint.y);

            // Xfinal = 2x1y1[2z1^2-(y1^2-x1^2)]
            cryptoMath.modMul(temp1, outputPoint.ta, point.curve.p, outputPoint.x);

            // Zfinal = (y1^2-x1^2)[2z1^2-(y1^2-x1^2)]
            cryptoMath.modMul(temp0, temp1, point.curve.p, outputPoint.z);

            return;
        }

        function addTed(point1 /*Q*/, point2 /*P*/, outputPoint) {

            var cm = cryptoMath;

            // var modulus = point1.curve.p;
            // var temp1 = [];

            if (typeof point1.ta === "undefined") {
                throw new Error("Point1 should be in Extended Projective form.");
            }

            if (typeof point2.ta === "undefined") {
                throw new Error("Point2 should be in Extended Projective form.");
            }
            var qq = convert_R1_to_R2(point1);

            addTedExtended(qq, point2, outputPoint);

            return;
        }

        function convert_R1_to_R2(point) {

            // tslint:disable-next-line: no-shadowed-variable
            var curve = point.curve,
                modulus = curve.p,
                qq = {
                    x: point.x.slice(),
                    y: point.y.slice(),
                    z: point.z.slice(),
                    td: [],
                    curve: point.curve
                };

            cryptoMath.modMul(point.ta, point.tb, modulus, conversionTemp0);

            cryptoMath.modMul(conversionTemp0, curve.d, modulus, qq.td);

            return qq;
        }

        function addTedExtended(qq /*Q*/, point2 /*P*/, outputPoint) {

            // Complete point addition P = P+Q, including the cases P!=Q, P=Q, P=-Q, P=neutral and Q=neutral
            // Twisted Edwards a=1 curve
            // Inputs: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to extended twisted
            //             Edwards coordinates(X1: Y1: Z1: T1)
            //         Q = (X2,Y2,Z2,dT2), corresponding to extended twisted Edwards coordinates
            //             (X2: Y2: Z2: T2)
            // Output: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to extended twisted
            //             Edwards coordinates(X1: Y1: Z1: T1)

            var cm = cryptoMath;
            var modulus = point2.curve.p;

            temp1 = []; temp2 = []; temp3 = [];

            //FP_MUL(P->Z, Q->Z, t3);             // t3 = Z1*Z2
            cm.modMul(point2.z, qq.z, modulus, temp3);

            //FP_MUL(P->Ta, P->Tb, t1);           // t1 = T1
            cm.modMul(point2.ta, point2.tb, modulus, temp1);

            //FP_ADD(P->X, P->Y, P->Ta);          // Ta = (X1+Y1)
            modAdd(point2.x, point2.y, point2.ta);

            //FP_MUL(t1, Q->Td, t2);              // t2 = dT1*T2
            cm.modMul(temp1, qq.td, modulus, temp2);

            //FP_ADD(Q->X, Q->Y, P->Tb);          // Tb = (X2+Y2)
            modAdd(qq.x, qq.y, point2.tb);

            //FP_SUB(t3, t2, t1);                 // t1 = theta
            modSub(temp3, temp2, temp1);

            //FP_ADD(t3, t2, t3);                 // t3 = alpha
            modAdd(temp3, temp2, temp3);

            //FP_MUL(P->Ta, P->Tb, t2);           // t2 = (X1+Y1)(X2+Y2)
            cm.modMul(point2.ta, point2.tb, modulus, temp2);

            //FP_MUL(P->X, Q->X, P->Z);           // Z = X1*X2
            cm.modMul(point2.x, qq.x, modulus, point2.z);

            //FP_MUL(P->Y, Q->Y, P->X);           // X = Y1*Y2
            cm.modMul(point2.y, qq.y, modulus, point2.x);

            //FP_SUB(t2, P->Z, t2);
            modSub(temp2, point2.z, temp2);

            //FP_SUB(P->X, P->Z, P->Ta);          // Tafinal = omega = Y1*Y2-X1*X2
            modSub(point2.x, point2.z, outputPoint.ta);

            //FP_SUB(t2, P->X, P->Tb);            // Tbfinal = beta = (X1+Y1)(X2+Y2)-X1*X2-Y1*Y2
            modSub(temp2, point2.x, outputPoint.tb);

            //FP_MUL(P->Ta, t3, P->Y);            // Yfinal = alpha*omega
            cm.modMul(outputPoint.ta, temp3, modulus, outputPoint.y);

            //FP_MUL(P->Tb, t1, P->X);            // Xfinal = beta*theta
            cm.modMul(outputPoint.tb, temp1, modulus, outputPoint.x);

            //FP_MUL(t3, t1, P->Z);               // Zfinal = theta*alpha
            cm.modMul(temp3, temp1, modulus, outputPoint.z);

            return;
        }

        function convertTedToWeierstrass(tedPoint, wPoint) {
            /// <summary></summary>
            /// <param name="tedPoint" type=""></param>
            /// <param name="outputPoint" type=""></param>

            var a = tedPoint.curve.a.slice(),
                d = tedPoint.curve.d.slice(),
                p = tedPoint.curve.p,
                modMul = cryptoMath.modMul,
                // tslint:disable-next-line: no-shadowed-variable
                modInv = cryptoMath.modInv;

            // t1 = 5
            temp1 = [5];

            // t2 = 5a
            modMul(a, temp1, p, temp2);

            // t2 = 5a-d
            modSub(temp2, d, temp2);

            // t3 = 5d
            modMul(d, temp1, p, temp3);

            // t1 = a-5d
            modSub(a, temp3, temp1);

            // t3 = yTE*(a-5d)
            modMul(tedPoint.y, temp1, p, temp3);

            // t2 = (5a-d) + yTE*(a-5d)
            modAdd(temp3, temp2, temp2);

            // t1 = 1
            temp1 = [1];

            // t3 = 1-yTE
            modSub(temp1, tedPoint.y, temp3);

            // t1 = 12
            temp1 = [12];

            // t4 = 12(1-yTE)
            modMul(temp1, temp3, p, temp4);

            // t4 = 1/12(1-yTE)
            modInv(temp4, p, temp4, true);

            // t1 = xTE*(1-yTE)
            modMul(tedPoint.x, temp3, p, temp1);

            // t3 = 2xTE*(1-yTE)
            modAdd(temp1, temp1, temp3);

            // t3 = 4xTE*(1-yTE)
            modAdd(temp3, temp3, temp3);

            // t3 = 1/4xTE*(1-yTE)
            modInv(temp3, p, temp3, true);

            // Xfinal = ((5a-d) + yTE*(a-5d))/12(1-yTE)
            modMul(temp4, temp2, p, wPoint.x);

            // t1 = 1
            temp1 = [1];

            // t1 = yTE+1
            modAdd(tedPoint.y, temp1, temp1);

            // t2 = a-d
            modSub(a, d, temp2);

            // t4 = (a-d)*(yTE+1)
            modMul(temp1, temp2, p, temp4);

            // Yfinal = ((a-d)*(yTE+1))/4xTE*(1-yTE)
            modMul(temp4, temp3, p, wPoint.y);

            return;
        }

        function convertWeierstrassToTed(wPoint, tedPoint) {

            var a = tedPoint.curve.a.slice(),
                d = tedPoint.curve.d.slice(),
                p = tedPoint.curve.p,
                modMul = cryptoMath.modMul,
                // tslint:disable-next-line: no-shadowed-variable
                modInv = cryptoMath.modInv;

            modAdd(wPoint.x, wPoint.x, temp1);

            modAdd(wPoint.x, temp1, temp1);

            // t1 = 6xW
            modAdd(temp1, temp1, temp1);

            // t2 = 6xW - a
            modSub(temp1, a, temp2);

            // t2 = 6xW - a - d
            modSub(temp2, d, temp2);

            modAdd(wPoint.y, wPoint.y, temp3);

            modAdd(wPoint.y, temp3, temp3);

            // t3 = 6yW
            modAdd(temp3, temp3, temp3);

            // t3 = 1/6yW
            modInv(temp3, p, temp3, true);

            // Xfinal = (6xW - a - d)/6yW
            modMul(temp2, temp3, p, tedPoint.x);

            // t1 = 12xW
            modAdd(temp1, temp1, temp1);

            // t2 = 12xW + d
            modAdd(temp1, d, temp2);

            // t1 = 12xW + a
            modAdd(temp1, a, temp1);

            modAdd(a, a, temp3);

            // t2 = 12xW + d - 2a
            modSub(temp2, temp3, temp2);

            // t2 = 12xW + d - 4a
            modSub(temp2, temp3, temp2);

            // t2 = 12xW + d - 5a
            modSub(temp2, a, temp2);

            modAdd(d, d, temp3);

            // t1 = 12xW + a - 2d
            modSub(temp1, temp3, temp1);

            // t1 = 12xW + a - 4d
            modSub(temp1, temp3, temp1);

            // t1 = 12xW + a - 5d
            modSub(temp1, d, temp1);

            // t1 = 1/(12xW + a - 5d)
            modInv(temp1, p, temp1, true);

            // Yfinal = (12xW + d - 5a)/(12xW + a - 5d)
            modMul(temp1, temp2, p, tedPoint.y);

            return;
        }

        var methods = {

            convertToMontgomeryForm: convertToMontgomeryForm,

            convertToStandardForm: convertToStandardForm,

            convertToAffineForm: convertToAffineForm,

            convertToJacobianForm: convertToJacobianForm,

            // For tests
            generatePrecomputationTable: function(w, generatorPoint) {
                /// <param name="w" type="Number"/>
                /// <param name="generatorPoint" type="EllipticCurvePointFp"/>

                return generatePrecomputationTable(w, generatorPoint);
            }

        };

        if (tedCurve) {

            methods.double = doubleTed;
            methods.add = addTed;
            methods.scalarMultiply = scalarMultiply;
            methods.normalize = normalizeTed;
            methods.convertToExtendedProjective = convertToExtendedProjective;
            methods.convertTedToWeierstrass = convertTedToWeierstrass;
            methods.convertWeierstrassToTed = convertWeierstrassToTed;
            methods.validatePoint = validatePointTed;
            methods.generatePrecomputationTable = function(w, generatorPoint) {
                /// <param name="w" type="Number"/>
                /// <param name="generatorPoint" type="EllipticCurvePointFp"/>

                return generatePrecomputationTableTed(w, generatorPoint);
            };
        } else {

            methods.double = double;
            methods.mixedDoubleAdd = mixedDoubleAdd;
            methods.mixedAdd = mixedAdd;
            methods.scalarMultiply = scalarMultiply;
            methods.negate = negate;
            methods.validatePoint = validatePoint;
        }

        return methods;

    };

    var sec1EncodingFp = function() {
        return {
            encodePoint: function(/*@type(EllipticCurvePointFp)*/ point) {
                /// <summary>Encode an EC point without compression.
                /// This function encodes a given points into a bytes array containing 0x04 | X | Y, where
                ///      X and Y are big endian bytes of x and y coordinates.</summary >
                /// <param name="point" type="EllipticCurvePointFp">Input EC point to encode.</param>
                /// <returns type="Array">A bytes array containing 0x04 | X | Y, where X and Y are big endian
                ///     encoded x and y coordinates.</returns >

                if (!point) {
                    throw new Error("point");
                }

                if (!point.isAffine) {
                    throw new Error("Point must be in affine form.");
                }

                if (point.isInMontgomeryForm) {
                    throw new Error("Point must not be in Montgomery form.");
                }

                if (point.isInfinity) {
                    return createArray(1); /* [0] */
                } else {
                    var xOctetString = cryptoMath.digitsToBytes(point.x);
                    var yOctetString = cryptoMath.digitsToBytes(point.y);
                    var pOctetString = cryptoMath.digitsToBytes(point.curve.p);     // just to get byte length of p
                    var mlen = pOctetString.length;
                    if (mlen < xOctetString.length || mlen < yOctetString.length) {
                        throw new Error("Point coordinate(s) are bigger than the field order.");
                    }
                    var output = createArray(2 * mlen + 1);       // for encoded x and y

                    output[0] = 0x04;
                    var offset = mlen - xOctetString.length;
                    for (var i = 0; i < xOctetString.length; i++) {
                        output[i + 1 + offset] = xOctetString[i];
                    }
                    offset = mlen - yOctetString.length;
                    for (i = 0; i < yOctetString.length; i++) {
                        output[mlen + i + 1 + offset] = yOctetString[i];
                    }

                    return output;
                }

            },
            decodePoint: function(encoded, curve) {
                /// <param name="encoded" type="Digits"/>
                /// <param name="curve" type="EllipticCurveFp"/>

                if (encoded.length < 1) {
                    throw new Error("Byte array must have non-zero length");
                }

                var pOctetString = cryptoMath.digitsToBytes(curve.p);
                var mlen = pOctetString.length;

                if (encoded[0] === 0x0 && encoded.length === 1) {
                    return curve.createPointAtInfinity();
                } else if (encoded[0] === 0x04 && encoded.length === 1 + 2 * mlen) {
                    // Standard encoding.
                    // Each point is a big endian string of bytes of length.
                    //      'ceiling(log_2(Q)/8)'
                    // Zero-padded and representing the magnitude of the coordinate.
                    var xbytes = createArray(mlen);
                    var ybytes = createArray(mlen);

                    for (var i = 0; i < mlen; i++) {
                        xbytes[i] = encoded[i + 1];
                        ybytes[i] = encoded[mlen + i + 1];
                    }

                    var x = cryptoMath.bytesToDigits(xbytes);
                    var y = cryptoMath.bytesToDigits(ybytes);

                    return EllipticCurvePointFp(curve, false, x, y);
                } else {
                    // We don't support other encoding features such as compression
                    throw new Error("Unsupported encoding format");
                }
            }
        };
    };

    var ModularSquareRootSolver = function(modulus) {
        /// <param name="modulus" type="Digits"/>

        // The modulus we are going to use.
        var p = modulus;

        // Special-K not just for breakfast anymore! This is k = (p-3)/4 + 1
        // which is used for NIST curves (or any curve of with P= 3 mod 4).
        // This field is null if p is not of the special form, or k if it is.
        var specialK = [];

        if (typeof modulus === "undefined") {
            throw new Error("modulus");
        }

        // Support for odd moduli, only.
        if (cryptoMath.isEven(modulus)) {
            throw new Error("Only odd moduli are supported");
        }

        // A montgomery multiplier object for doing fast squaring.
        var mul = cryptoMath.MontgomeryMultiplier(p);

        // 'p === 3 mod 4' then we can use the special super fast version.
        // Otherwise we must use the slower general case algorithm.
        if (p[0] % 4 === 3) {
            // 'special k = (p + 1) / 4'
            cryptoMath.add(p, cryptoMath.One, specialK);
            cryptoMath.shiftRight(specialK, specialK, 2);
        } else {
            specialK = null;
        }

        // Temp storage
        var temp0 = new Array(p.length);
        var temp1 = new Array(p.length);

        function squareRootNistCurves(a) {
            /// <summary>Given a number a, returns a solution x to x^2 = a (mod p).</summary>
            /// <param name="a" type="Array">An integer a.</param>
            /// <returns type="Array">The square root of the number a modulo p, if it exists,
            /// otherwise null.</returns>

            // beta = a^k mod n where k=(n+1)/4 for n == 3 mod 4, thus a^(1/2) mod n
            var beta = cryptoMath.intToDigits(0, 16);
            mul.modExp(a, specialK, beta);

            // Okay now we gotta double check by squaring.
            var aPrime = [0];
            cryptoMath.modMul(beta, beta, mul.m, aPrime);

            // If a != x^2 then a has no square root
            if (cryptoMath.compareDigits(a, aPrime) !== 0) {
                return null;
            }

            return beta;
        }

        var publicMethods = {

            squareRoot: function(a) {
                if (specialK !== null) {
                    // Use the special case fast code
                    return squareRootNistCurves(a);
                } else {
                    // Use the general case code
                    throw new Error("GeneralCase not supported.");
                }
            },

            // Given an integer a, this routine returns the Jacobi symbol (a/p),
            // where p is the modulus given in the constructor, which for p an
            // odd prime is also the Legendre symbol. From "Prime Numbers, A
            // Computational Perspective" by Crandall and Pomerance, alg. 2.3.5.
            // The Legendre symbol is defined as:
            //   0   if a === 0 mod p.
            //   1   if a is a quadratic residue (mod p).
            //   -1  if a is a quadratic non-reside (mod p).
            jacobiSymbol: function(a) {
                /// <param name="a">An integer a.</param>

                var modEightMask = 0x7,
                    modFourMask = 0x3,
                    aPrime,
                    pPrime;

                // Clone our inputs, we are going to destroy them
                aPrime = a.slice();
                pPrime = p.slice();

                // 'a = a mod p'.
                cryptoMath.reduce(aPrime, pPrime, aPrime, temp0, temp1);

                // 't = 1'
                var t = 1;

                // While (a != 0)
                while (!cryptoMath.isZero(aPrime)) {
                    // While a is even
                    while (cryptoMath.isEven(aPrime)) {
                        // 'a <- a / 2'
                        cryptoMath.shiftRight(aPrime, aPrime);

                        // If (p mod 8 in {3,5}) t = -t;
                        var pMod8 = pPrime[0] & modEightMask;
                        if (pMod8 === 3 || pMod8 === 5) {
                            t = -t;
                        }
                    }

                    // Swap variables
                    // (a, p) = (p, a).
                    var tmp = aPrime;
                    aPrime = pPrime;
                    pPrime = tmp;

                    // If (a === p === 3 (mod 4)) t = -t;
                    var aMod4 = aPrime[0] & modFourMask;
                    var pMod4 = pPrime[0] & modFourMask;
                    if (aMod4 === 3 && pMod4 === 3) {
                        t = -t;
                    }

                    // 'a = a mod p'
                    cryptoMath.reduce(aPrime, pPrime, aPrime, temp0, temp1);
                }

                // If (p == 1) return t else return 0
                if (cryptoMath.compareDigits(pPrime, cryptoMath.One) === 0) {
                    return t;
                } else {
                    return 0;
                }
            }

        };

        return publicMethods;
    };

    var curvesInternal = {};

    var createCurve = function(curveName) {

        var curveData = curvesInternal[curveName.toUpperCase()];

        if (!curveData) {
            throw new Error(curveName + " Unsupported curve.");
        }

        if (curveData.type === 0) {
            return createWeierstrassCurve(curveData);
        }

        if (curveData.type === 1) {
            return createTedCurve(curveData);
        }

        throw new Error(curveName + " Unsupported curve type.");
    };

    var validateEccPoint = function(curveName, x, y, z) {
        var curve = createCurve(curveName);
        var point = new EllipticCurvePointFp(curve, false, btd(x), btd(y), z && btd(z), false);
        var opp = new EllipticCurveOperatorFp(curve);
        return opp.validatePoint(point);
    };

    return {
        createCurve: createCurve,
        curves: curvesInternal,
        sec1EncodingFp: sec1EncodingFp,
        validatePoint: validateEccPoint,
        EllipticCurvePointFp: EllipticCurvePointFp,
        EllipticCurveOperatorFp: EllipticCurveOperatorFp,
        ModularSquareRootSolver: ModularSquareRootSolver
    };
}

var cryptoECC = cryptoECC || MsrcryptoECC();
