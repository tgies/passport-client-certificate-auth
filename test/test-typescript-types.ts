/**
 * Type-check only test file - verifies TypeScript consumer experience.
 * This file is not executed, only type-checked by `npm run typecheck`.
 */
import { Strategy } from '../index.js';
import type {
    StrategyOptions,
    StrategyOptionsWithReq,
    StrategyOptionsWithoutReq,
    VerifyFunction,
    VerifyFunctionWithRequest,
    VerifyCallback,
    ClientCertRequest,
    CertificateSource,
    HeaderEncoding,
} from '../index.js';

// Test 1: Basic constructor with verify function only
const _basic = new Strategy((cert, done) => {
    const _cn: string | undefined = cert.subject?.CN;
    done(null, { name: _cn });
});

// Test 2: Constructor with options and verify
const _withOptions = new Strategy({
    certificateSource: 'aws-alb',
    fallbackToSocket: true,
}, (cert, done) => {
    done(null, { cn: cert.subject?.CN });
});

// Test 3: passReqToCallback with request in verify
const _withReq = new Strategy({
    passReqToCallback: true,
}, (req, cert, done) => {
    const _url: string | undefined = req.url;
    done(null, { cn: cert.subject?.CN });
});

// Test 4: Strategy name property
const _name: string = _basic.name;

// Test 5: Full options (using StrategyOptionsWithoutReq for type narrowing)
const fullOptions: StrategyOptionsWithoutReq = {
    name: 'custom-cert',
    passReqToCallback: false,
    certificateSource: 'aws-alb',
    certificateHeader: 'x-client-cert',
    headerEncoding: 'url-pem',
    fallbackToSocket: true,
    includeChain: true,
    verifyHeader: 'X-SSL-Verify',
    verifyValue: 'SUCCESS',
    onAuthenticated: (cert, req) => {
        void cert.subject;
        void req.url;
    },
    onRejected: (cert, req, reason) => {
        void reason;
    },
};
const _full = new Strategy(fullOptions, (cert, done) => done(null, {}));

// Test 5b: StrategyOptions interface is assignable (base type check)
const _baseOpts: StrategyOptions = fullOptions;

// Test 6: VerifyFunction type
const verify: VerifyFunction = (cert, done) => {
    done(null, { cn: cert.subject?.CN });
};
const _fromVerify = new Strategy(verify);

// Test 7: VerifyFunctionWithRequest type
const verifyWithReq: VerifyFunctionWithRequest = (req, cert, done) => {
    done(null, { url: req.url, cn: cert.subject?.CN });
};
const _fromVerifyWithReq = new Strategy({ passReqToCallback: true }, verifyWithReq);

// Test 8: VerifyCallback type
const _cb: VerifyCallback = (err, user, info) => {
    if (err) { void err.message; }
    if (user) { void user; }
    if (info) { void info; }
};

// Test 9: CertificateSource and HeaderEncoding types
const _source: CertificateSource = 'cloudflare';
const _encoding: HeaderEncoding = 'base64-der';

// Test 10: ClientCertRequest has clientCertificate
function checkRequest(req: ClientCertRequest): void {
    if (req.clientCertificate) {
        const _cn: string | undefined = req.clientCertificate.subject?.CN;
        void _cn;
    }
}

// Test 11: StrategyOptionsWithoutReq and StrategyOptionsWithReq
const _optsNoReq: StrategyOptionsWithoutReq = { passReqToCallback: false };
const _optsWithReq: StrategyOptionsWithReq = { passReqToCallback: true };

// Negative type tests

// Test 12: Strategy requires a verify function argument
// @ts-expect-error - no arguments
const _noArgs = new Strategy();

// Test 13: certificateSource must be a valid preset
const badSourceOpts = { certificateSource: 'invalid-source' as const };
// @ts-expect-error - 'invalid-source' is not a valid CertificateSource
const _badSource = new Strategy(badSourceOpts, verify);

// Test 14: headerEncoding must be a valid value
const badEncodingOpts = { headerEncoding: 'invalid-encoding' as const };
// @ts-expect-error - 'invalid-encoding' is not a valid HeaderEncoding
const _badEncoding = new Strategy(badEncodingOpts, verify);

// Test 15: fallbackToSocket must be boolean
const badFallbackOpts = { fallbackToSocket: 'yes' as const };
// @ts-expect-error - string is not boolean
const _badFallback = new Strategy(badFallbackOpts, verify);

// Suppress unused variable warnings
void _basic;
void _withOptions;
void _withReq;
void _name;
void _full;
void _baseOpts;
void _fromVerify;
void _fromVerifyWithReq;
void _cb;
void _source;
void _encoding;
void checkRequest;
void _optsNoReq;
void _optsWithReq;
void _noArgs;
void _badSource;
void _badEncoding;
void _badFallback;
