const fs = require("fs");
const gulp = require("gulp");
const concat = require("gulp-concat");
const strip = require("gulp-strip-comments");
const header = require("gulp-header");
const beautify = require("gulp-beautify");
const minify = require("gulp-minify");
const clean = require("gulp-clean");
const removeTest = require("gulp-strip-code");

const outputFiles = [
    "lib/msrcrypto.js",
    "lib/msrcrypto.min.js"
];

const subtleBuild = [
    "scripts/subtle/head.js",
    "scripts/subtle/syncWorker.js",
    "scripts/subtle/operations.js",
    "scripts/subtle/keyManager.js",
    "scripts/subtle/workerManager.js",
    "scripts/subtle/subtleInterface.js",
    "scripts/subtle/tail.js"
];

const fullBuild = [
    "scripts/bundleHead.js",
    "scripts/operations.js",
    "scripts/global.js",
    "scripts/utilities.js",
    "scripts/asn1.js",
    "scripts/worker.js",
    "scripts/jwk.js",
    "scripts/cryptoMath.js",
    "scripts/cryptoECC.js",
    "scripts/curves_NIST.js",
    "scripts/curves_BN.js",
    "scripts/curves_NUMS.js",
    "scripts/sha.js",
    "scripts/sha1.js",
    "scripts/sha256.js",
    "scripts/sha512.js",
    "scripts/hmac.js",
    "scripts/aes.js",
    "scripts/aes-cbc.js",
    "scripts/aes-gcm.js",
    "scripts/random.js",
    "scripts/entropy.js",
    "scripts/prime.js",
    "scripts/rsa-base.js",
    "scripts/rsa-oaep.js",
    "scripts/rsa-pkcs1.js",
    "scripts/rsa-pss.js",
    "scripts/rsa.js",
    "scripts/kdf.js",
    "scripts/pbkdf2.js",
    "scripts/ecdh.js",
    "scripts/ecdsa.js",
    "scripts/subtle.js",
    "scripts/wrapKey.js",
    "scripts/bundleTail.js",
    "scripts/subtle/promises.js"
];

const aesBuild = [
    "scripts/bundleHead.js",
    "scripts/operations.js",
    "scripts/global.js",
    "scripts/utilities.js",
    "scripts/worker.js",
    "scripts/jwk.js",
    "scripts/sha.js",
    "scripts/sha1.js",
    "scripts/sha256.js",
    "scripts/sha512.js",
    "scripts/hmac.js",
    "scripts/aes.js",
    "scripts/aes-cbc.js",
    "scripts/aes-gcm.js",
    "scripts/random.js",
    "scripts/entropy.js",
    "scripts/subtle.js",
    "scripts/wrapKey.js",
    "scripts/bundleTail.js",
    "scripts/subtle/promises.js"
];

const testBuild = fullBuild.concat([
    "scripts/testInterface.js"
]);

// Delete the old output files before building.
function cleanBuild() {
    return gulp.src(outputFiles, { read: false, allowEmpty: true })
        .pipe(clean());
}

// Build the subtle.js file from a set of individual files.
function subtle() {
    return gulp.src(subtleBuild)
        .pipe(concat("subtle.js"))      // concatenate scripts into single UMD module
        .pipe(strip({ trim: true }))    // strip the comments out
        .pipe(beautify.js({ indent_size: 4, no_preserve_newlines: true }))  // format the code
        .pipe(header(fs.readFileSync("LICENSE", "utf8")))    // add a copyright/license header
        .pipe(gulp.dest("scripts"));    // write the file to the lib folder
}

// Concat the files into a single bundle.
function bundle() {
    return gulp.src(fullBuild)
        .pipe(concat("msrcrypto.js"))   // concatenate scripts into single UMD module
        .pipe(gulp.dest("lib"));        // write the file to the lib folder
}

// Clean and format the new bundle.
function format() {
    return gulp.src(
        [
            "lib/msrcrypto.js"
        ])
        .pipe(removeTest({ start_comment: "debug-block", end_comment: "end-debug-block" })) // strip out test/debug code
        .pipe(clean())
        .pipe(strip({ trim: true }))    // strip the comments out
        .pipe(beautify.js({ indent_size: 4, no_preserve_newlines: true }))  // format the code
        .pipe(gulp.dest("lib"));    // write the file to the lib folder
}

// Minify the new bundle to a .min.js file.
function minifyBundle() {
    return gulp.src(
        [
            "lib/msrcrypto.js"
        ])
        .pipe(minify({
            ext: { min: ".min.js" }
            //compress: {
            //    global_defs: {DEBUG: false}
            //}
        }))
        .pipe(gulp.dest("lib"));    // write the file to the lib folder
}

// Add the copyright/license header to output files.
function addCopyrightHeaders() {
    return gulp.src(outputFiles)
        .pipe(header(fs.readFileSync("LICENSE", "utf8")))    // add a copyright/license header
        .pipe(gulp.dest("lib"));    // write the file to the lib folder
}

gulp.task("default", gulp.series(cleanBuild, subtle, bundle, format, minifyBundle, addCopyrightHeaders));

// To run the default: >.\node_modules\.bin\gulp
