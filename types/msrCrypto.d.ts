// Type definitions for @microsoft/msrcrypto.
//
// msrCrypto exposes a single object that mirrors the W3C Web Cryptography API
// (`crypto` / `crypto.subtle`) plus a handful of library-specific helpers.
// The shape is described directly here rather than by augmenting the global
// `Crypto` interface, so importing this module does not change the types of the
// platform's own `crypto` object.
//
// DOM types (CryptoKey, CryptoKeyPair, JsonWebKey, etc.) come from lib.dom.d.ts.

export = msrCrypto;

declare const msrCrypto: msrCrypto.MsrCrypto;

declare namespace msrCrypto {
    /** Anything msrCrypto accepts as a byte buffer: a plain array of byte values, an ArrayBuffer, or a typed-array view. */
    type ByteSource = ArrayLike<number> | ArrayBuffer | ArrayBufferView;

    /** A hash may be given as a string ("SHA-256") or as an object ({ name: "SHA-256" }). */
    type HashAlgorithmIdentifier = string | { name: string };

    /**
     * An algorithm may be given as a string ("AES-GCM") or as an algorithm
     * object ({ name: "AES-GCM", ... }), per the W3C AlgorithmIdentifier
     * (object or DOMString).
     */
    type MsrAlgorithmIdentifier = string | MsrAlgorithm;

    type KeyFormat = "raw" | "spki" | "pkcs8" | "jwk";

    /**
     * A permissive algorithm parameter object. msrCrypto accepts the standard
     * WebCrypto algorithm fields, but byte-valued fields (iv, salt, ...) may be
     * supplied as plain arrays or typed arrays in addition to ArrayBuffers.
     */
    interface MsrAlgorithm {
        name: string;
        /** SHA / HMAC / RSA hash. */
        hash?: HashAlgorithmIdentifier;
        /** Key or output length in bits (AES, HMAC, deriveBits, ...). */
        length?: number;
        // AES-CBC / AES-GCM / AES-CTR
        iv?: ByteSource;
        counter?: ByteSource;
        additionalData?: ByteSource;
        tagLength?: number;
        // RSA
        modulusLength?: number;
        publicExponent?: ByteSource;
        saltLength?: number;
        label?: ByteSource;
        // Elliptic curve (ECDH / ECDSA)
        namedCurve?: string;
        /** ECDH peer public key (passed in the algorithm for deriveBits/deriveKey). */
        public?: CryptoKey;
        // Key-derivation (PBKDF2 / HKDF / Concat)
        salt?: ByteSource;
        info?: ByteSource;
        iterations?: number;
        /** Request a streaming operation; the call resolves with a StreamObject. */
        stream?: boolean;
    }

    /**
     * Returned when a subtle operation is started in streaming mode (the data
     * argument is omitted, or algorithm.stream is true). Feed data with
     * `process`, then call `finish` to obtain the final result.
     */
    interface StreamObject {
        process(data: ByteSource): Promise<ArrayBuffer>;
        finish(): Promise<ArrayBuffer>;
        abort(): void;
    }

    /** ASN.1 DER encoder/decoder exposed as `msrCrypto.asn1`. */
    interface Asn1Node {
        type?: string;
        header?: number;
        length?: number;
        contents?: number[];
        children?: Asn1Node[];
        [key: string]: unknown;
    }

    interface Asn1 {
        parse(bytes: ByteSource, force?: boolean): Asn1Node;
        encode(node: Asn1Node | object): number[];
        toString(objTree: Asn1Node | object): string;
    }

    /** The msrCrypto SubtleCrypto-like interface. */
    interface MsrSubtleCrypto {
        encrypt(algorithm: MsrAlgorithmIdentifier, key: CryptoKey, data: ByteSource): Promise<ArrayBuffer>;
        encrypt(algorithm: MsrAlgorithmIdentifier, key: CryptoKey): Promise<StreamObject>;

        decrypt(algorithm: MsrAlgorithmIdentifier, key: CryptoKey, data: ByteSource): Promise<ArrayBuffer>;
        decrypt(algorithm: MsrAlgorithmIdentifier, key: CryptoKey): Promise<StreamObject>;

        sign(algorithm: MsrAlgorithmIdentifier, key: CryptoKey, data: ByteSource): Promise<ArrayBuffer>;
        sign(algorithm: MsrAlgorithmIdentifier, key: CryptoKey): Promise<StreamObject>;

        verify(algorithm: MsrAlgorithmIdentifier, key: CryptoKey, signature: ByteSource, data: ByteSource): Promise<boolean>;
        verify(algorithm: MsrAlgorithmIdentifier, key: CryptoKey, signature: ByteSource): Promise<StreamObject>;

        digest(algorithm: MsrAlgorithmIdentifier, data: ByteSource): Promise<ArrayBuffer>;
        digest(algorithm: MsrAlgorithmIdentifier): Promise<StreamObject>;

        generateKey(algorithm: MsrAlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey | CryptoKeyPair>;

        deriveKey(algorithm: MsrAlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: MsrAlgorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;

        deriveBits(algorithm: MsrAlgorithmIdentifier, baseKey: CryptoKey, length: number): Promise<ArrayBuffer>;

        importKey(format: "jwk", keyData: JsonWebKey, algorithm: MsrAlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
        importKey(format: "raw" | "spki" | "pkcs8", keyData: ByteSource, algorithm: MsrAlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;

        exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;
        exportKey(format: "raw" | "spki" | "pkcs8", key: CryptoKey): Promise<ArrayBuffer>;

        wrapKey(format: KeyFormat, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: MsrAlgorithmIdentifier): Promise<ArrayBuffer>;

        unwrapKey(format: KeyFormat, wrappedKey: ByteSource, unwrappingKey: CryptoKey, unwrapAlgorithm: MsrAlgorithmIdentifier, unwrappedKeyAlgorithm: MsrAlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
    }

    /** The object returned when importing the library. */
    interface MsrCrypto {
        /** The SubtleCrypto-like interface. */
        readonly subtle: MsrSubtleCrypto;

        /** The Web Crypto CryptoKey constructor (used for instanceof checks). */
        readonly CryptoKey: typeof CryptoKey;

        /** The Promise constructor msrCrypto uses (native Promise when available, otherwise the bundled polyfill). */
        readonly Promise: PromiseConstructor;

        /** Fill an array (or typed array) with cryptographically random values and return it. */
        getRandomValues<T extends ArrayBufferView>(array: T): T;
        getRandomValues(array: number[]): number[];

        /** Seed or reseed the PRNG with additional entropy. */
        initPrng(entropyData: ArrayLike<number>): void;

        /** Convert bytes to a Base64 (or Base64Url) string. */
        toBase64(data: ByteSource, base64Url?: boolean): string;

        /** Decode a Base64/Base64Url string to an array of byte values. */
        fromBase64(base64String: string): number[];

        /** Encode UTF-8/ASCII text to an array of byte values. */
        textToBytes(text: string): number[];

        /** Decode an array of bytes as UTF-8/ASCII text. */
        bytesToText(bytes: ByteSource): string;

        /** ASN.1 DER encoder/decoder. */
        readonly asn1: Asn1;

        /** URL of the loaded msrCrypto script (when determinable). */
        readonly url: string;

        /** Library version string. */
        readonly version: string;

        /** Enable or disable use of web workers (when supported by the host). */
        useWebWorkers(useWebWorkers: boolean): void;
    }
}

