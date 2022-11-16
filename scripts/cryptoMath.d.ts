type Digits = number[];
type Digit = number;
type Bytes = number[];
type Byte = number;

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

export class MontgomeryMultiplier {
    constructor(modulus: Digits, context?: ComputeContext)
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
    public convertToMontgomeryForm(digits: Digits): Digits
    public convertToStandardForm(digits: Digits): Digits
    public montgomeryMultiply(multiplicand: Digits, multiplier: Digits, result: Digits, ctx?: ComputeContext): void
    public modExp(base: Digits, exponent: Digits, result: Digits, skipSideChannel: boolean): Digits
    public reduce(digits: Digits, result: Digits): void
}

export class IntegerGroup {
    constructor(modulusBytes: Bytes)
    public m_modulus: Digits
    public m_digitWidth: number
    public montmul: MontgomeryMultiplier
    public createElementFromInteger(interger: number): IntegerGroupElement
    public createElementFromBytes(bytes: Bytes): IntegerGroupElement
    public createElementFromDigits(digits: Digits): IntegerGroupElement
    public equals(group: IntegerGroup): boolean
    public add(addend1: IntegerGroupElement, addend2: IntegerGroupElement, sum: IntegerGroupElement): void
    public subtract(leftElement: IntegerGroupElement, rightElement: IntegerGroupElement, outputElement: IntegerGroupElement): void
    public multiply(multiplicand: IntegerGroupElement, multiplier: IntegerGroupElement, product: IntegerGroupElement): IntegerGroupElement
    public inverse(element: IntegerGroupElement, outputElement: IntegerGroupElement): void
    public modexp(valueElement: IntegerGroupElement, exponent: IntegerGroupElement, outputElement: IntegerGroupElement): IntegerGroupElement
}

interface IntegerGroupElement {
    m_digits: Digits,
    m_group: IntegerGroup,
    equals: (element: IntegerGroupElement) => boolean
}


export const DIGIT_BITS: number
export const DIGIT_NUM_BYTES: number
export const DIGIT_MASK: number
export const DIGIT_BASE: number
export const DIGIT_MAX: number
export const Zero: [0]
export const One: [1]
export const normalizeDigitArray: (digits: Digits, length?: number, pad?: boolean) => Digits
export const bytesToDigits: (bytes: Bytes) => Digits
export const stringToDigits: (text: string) => Digits
export const digitsToString: (digits: Digits) => string
export const intToDigits: (integer: number) => Digits
export const digitsToBytes: (digits: Digits) => Bytes
export const isZero: (array: Array<Byte | Digit>) => boolean
export const isEven: (array: Array<Byte | Digit>) => boolean
export const shiftRight: (source: Digits, destination: Digits, bits?: number, length?: number) => Digits
export const shiftLeft: (source: Digits, destination: Digits, bits?: number, length?: number) => Digits
export const compareDigits: (left: Digits, right: Digits) => number
export const highestSetBit: (bytes: Bytes) => number
export const fixedWindowRecode: (digits: Digits, windowSize: number, t: number) => Digits
export const add: (addend1: Digits, addend2: Digits, sum: Digits) => Digit
export const subtract: (minuend: Digits, subtrahend: Digits, difference: Digits) => Digit
export const multiply: (a: Digits, b: Digits | Digit, p: Digits) => Digits
export const divRem: (dividend: Digits, divisor: Digits, quotient: Digits, remainder: Digits, temp1?: Digits, temp2?: Digits) => void
export const reduce: (number: Digits, modulus: Digits, remainder: Digits, temp1?: Digits, temp2?: Digits) => Digits
export const modInv: (a: Digits, n: Digits, aInv?: Digits, pad?: boolean) => Digits
export const modInvCT: (a: Digits, n: Digits, aInv?: Digits) => Digits
export const modExp: (base: Digits, exponent: Digits, modulus: Digits, result?: Digits) => Digits
export const modMul: (multiplicand: Digits, multiplier: Digits | Digit, modulus: Digits, product?: Digits, temp1?: Digits, temp2?: Digits) => Digits
export const createArray: (value: number | number[]) => Array<number>
