interface ComputeContext {
    m: Digits,
    mPrime: number,
    m0: number,
    mu: number,
    rModM: Digits,
    rSquaredModm: Digits,
    rCubedModm: Digits,
    temp1: Digits,
    temp2: Digits
}

class MontgomeryMultiplier {
    public m: Digits
    public mPrime: number
    public m0: number
    public mu: number
    public rModM: Digits
    public rSquaredModm: Digits
    public rCubedModm: Digits
    public temp1: Digits
    public temp2: Digits
    public one: [1]
    public s: number
    public ctx: ComputeContext
    public convertToMontgomeryForm (digits: Digits) :Digits
    public convertToStandardForm (digits: Digits) : Digits
    public montgomeryMultiply (multiplicand: Digits, multiplier: Digits, result: Digits, ctx?: ComputeContext) : void
    public modExp (base: Digits, exponent: Digits, result: Digits, skipSideChannel: boolean) : Digits
    public reduce (digits: Digits, result: Digits) : void
}

class IntegerGroup {
    public m_modulus: Digits
    public m_digitWidth: number
    public montmul: MontgomeryMultiplier
    public createElementFromInteger (interger: number) : IIntegerGroupElement
    public createElementFromBytes (bytes: Bytes) : IIntegerGroupElement
    public createElementFromDigits (digits: Digits) : IIntegerGroupElement
    public equals (group: IntegerGroup) : boolean
    public add (addend1: IIntegerGroupElement, addend2: IIntegerGroupElement, sum: IIntegerGroupElement) : void
    public subtract (leftElement: IIntegerGroupElement, rightElement: IIntegerGroupElement, outputElement: IIntegerGroupElement) : void
    public multiply (multiplicand: IIntegerGroupElement, multiplier: IIntegerGroupElement, product: IIntegerGroupElement) : IIntegerGroupElement
    public inverse (element: IIntegerGroupElement, outputElement: IIntegerGroupElement) : void
    public modexp (valueElement: IIntegerGroupElement, exponent: IIntegerGroupElement, outputElement: IIntegerGroupElement): IIntegerGroupElement
}

interface IIntegerGroupElement {
    m_digits: digits,
    m_group: group,
    equals: (element: IIntegerGroupElement) => boolean
}

interface ICryptoMath {
    DIGIT_BITS: number,
    DIGIT_NUM_BYTES: number,
    DIGIT_MASK: number,
    DIGIT_BASE: number,
    DIGIT_MAX: number,
    Zero: [0],
    One: [1],
    normalizeDigitArray: (digits: Digits, length?: number, pad?: boolean) => Digits,
    bytesToDigits: (bytes: Bytes) => Digits,
    stringToDigits: (text: string) => Digits,
    digitsToString: (digits: Digits) => string,
    intToDigits: (integer: number) => Digits,
    digitsToBytes: (digits: Digits) => Bytes,
    isZero: (array: Array<Byte | Digit>) => boolean,
    isEven: (array: Array<Byte | Digit>) => boolean,
    shiftRight: (source: Digits, destination: Digits, bits: number = 1, length?: number) => Digits,
    shiftLeft: (source: Digits, destination: Digits, bits: number = 1, length?: number) => Digits,
    compareDigits: (left: Digits, right: Digits) => number,
    highestSetBit: (bytes: Bytes) => number,
    fixedWindowRecode: (digits: Digits, windowSize: number, t: number) => Digits,
    IntegerGroup: (modulus: Digits) => IntegerGroup,
    add: (addend1: Digits, addend2: Digits, sum: Digits) => Digit,
    subtract: (minuend: Digits, subtrahend: Digits, difference: Digits) => Digit,
    multiply: (a: Digits, b: Digits | Digit, p: Digits) => Digits,
    divRem: (dividend: Digits, divisor: Digits, quotient: Digits, remainder: Digits, temp1?: Digits, temp2?: Digits) => void,
    reduce: (number: Digits, modulus: Digits, remainder: Digits, temp1?: Digits, temp2?: Digits) => Digits,
    modInv: (a: Digits, n: Digits, aInv?: Digits, pad: boolean = true) => Digits,
    modInvCT: (a: Digits, n: Digits, aInv?: Digits) => Digits,
    modExp: (base: Digits, exponent: Digits, modulus: Digits, result?: Digits) => Digits,
    modMul: (multiplicand: Digits, multiplier: Digits | Digit, modulus: Digits, product?: Digits, temp1?: Digits, temp2?: Digits) => Digits,
    createArray: (value: number | number[]) => Array<number>,
    MontgomeryMultiplier: (modulus: Digits, context: ComputeContext) => MontgomeryMultiplier
}

export const cryptoMath : ICryptoMath;