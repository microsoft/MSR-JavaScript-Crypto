// Type definitions for @microsoft/msrcrypto.
// The library exposes a WebCrypto-compatible `Crypto` object (from lib.dom.d.ts)
// with a few msrCrypto-specific extras.

export = msrCrypto;

declare const msrCrypto: Crypto;

declare global {
    // Extend default Crypto from lib.dom.d.ts to add msrCrypto extras
    interface Crypto {
        initPrng(entropyData: ArrayLike<number>): void;
        toBase64(data: ArrayLike<number> | ArrayBuffer, toBase64Url?: boolean): string;
        fromBase64(data: string): number[];
        textToBytes(text: string): number[];
        bytesToText(bytes: ArrayLike<number>): string;
        CryptoKey: typeof CryptoKey;
        Promise: typeof Promise;
    }

    // Extend default Algorithm from lib.dom.d.ts
    //interface Algorithm {
    //    salt?: ArrayLike<number>,
    //    namedCurve?: string,
    //    iv?: ArrayLike<number>,
    //    tagLength?: number,
    //    additionalData?: ArrayLike<number>,
    //    hash?: { name: string },
    //    length?: number,
    //    stream?: boolean
    //}

    // Support msrCrypto streaming with new StreamObject
    interface StreamObject {
        process(data: ArrayBuffer | ArrayLike<number>): PromiseLike<ArrayBuffer | ArrayLike<number> | void>;
        finish(): PromiseLike<ArrayBuffer | ArrayLike<number>>;
        abort(): PromiseLike<void>;
    }
}

