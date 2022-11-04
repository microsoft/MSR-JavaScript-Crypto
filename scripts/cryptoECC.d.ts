declare class EllipticCurveBase {
    public p: Digits
    public a: Digits
    public order: Digits
    public gx: Digits
    public gy: Digits
    public allocatePointStorage(): EllipticCurvePointFp
    public createPointAtInfinity(): EllipticCurvePointFp
}

declare class EllipticCurveFpB extends EllipticCurveBase {
    public b: Digits
}

declare class EllipticCurveFpD extends EllipticCurveBase {
    public d: Digits
}

type EllipticCurveFp = EllipticCurveFpB | EllipticCurveFpD;

type Digit = number;
type Digits = Array<Digit>;

type Byte = number;
type Bytes = Array<Byte>;

type EncodedCurve = Array<number>;

declare class EllipticCurvePointFp {
    public curve: EllipticCurveFp;
    public isInfinity: boolean;
    public x: Digits;
    public y: Digits;
    public z: Digits;
    public isInMontgomeryForm: boolean;
    public isInfinity: boolean;
    public isAffine: boolean;
    constructor(curve: EllipticCurveFp, isInfinity: boolean, x: Digits, y: Digits, z?: Digits, isInMontgomeryForm: boolean = false)
    public equals(point: EllipticCurvePointFp): boolean
    public copyTo(source: EllipticCurvePointFp, destination: EllipticCurvePointFp): void
    public clone(): EllipticCurvePointFp
}

class WeierstrassCurve extends EllipticCurveFpB {
    public type: number
    public name: string
    public generator: EllipticCurvePointFp
}

class TedCurve extends EllipticCurveFpD {
    type: number
    name: string
    rbits: number
    generator: EllipticCurvePointFp
}

function createCurve(curveName: string): WeierstrassCurve | TedCurve
function sec1EncodingFp(): {
    encodePoint(point: EllipticCurvePointFp): EncodedCurve,
    decodePoint(encoded: EncodedCurve, curve: EllipticCurveFp)
}
function validatePoint(curveName: string, x: Bytes, y: Bytes, z: Bytes): boolean;
function ModularSquareRootSolver(modulus: Digits): {
    squareRoot(digits: Digits): Digits,
    jacobiSymbol(digits: Digits): number
}
function EllipticCurveOperatorFp(curve: EllipticCurveFp) : {
    convertToMontgomeryForm(point : EllipticCurvePointFp) : void,
    convertToStandardForm(point : EllipticCurvePointFp) : void,
    convertToAffineForm(point : EllipticCurvePointFp) : void,
    convertToJacobianForm(point : EllipticCurvePointFp) : void,
    scalarMultiply(k : Digits, point : EllipticCurvePointFp, outputPoint : EllipticCurvePointFp, multiplyBy4? : boolean) : void,
    mixedAdd(jacobianPoint: EllipticCurvePointFp, affinePoint: EllipticCurvePointFp, outputPoint: EllipticCurvePointFp)  : void,
    mixedDoubleAdd(jacobianPoint: EllipticCurvePointFp, affinePoint: EllipticCurvePointFp, outputPoint: EllipticCurvePointFp) : void,
    double(point: EllipticCurvePointFp, outputPoint: EllipticCurvePointFp) : void,
    negate(point: EllipticCurvePointFp, outputPoint: EllipticCurvePointFp) : void,
}

export const cryptoECC = {
    createCurve,
    sec1EncodingFp,
    validatePoint,
    EllipticCurvePointFp,
    EllipticCurveOperatorFp,
    ModularSquareRootSolver
}
