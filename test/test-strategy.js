/*!
 * passport-client-certificate-auth - Tests
 * Copyright (C) 2026 Tony Gies
 * @license MIT
 */

import { jest } from '@jest/globals';
import Strategy from '../lib/strategy.js';
import { generate } from 'selfsigned';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const mockCert = {
    subject: { CN: 'test-client', O: 'Test Org', OU: 'Engineering' },
    issuer: { CN: 'Test CA', O: 'Test Org' },
    fingerprint: 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01',
    fingerprint256: 'SHA256:AB:CD:EF',
    serialNumber: '01:23:45:67:89:AB:CD:EF',
    valid_from: 'Jan  1 00:00:00 2024 GMT',
    valid_to: 'Dec 31 23:59:59 2026 GMT',
};

/**
 * Build a mock request with socket-based cert.
 */
function dummyReq(authorized, cert, headers) {
    return {
        socket: {
            authorized,
            getPeerCertificate: jest.fn((detailed) => {
                if (detailed && cert) {
                    return { ...cert, issuerCertificate: { subject: { CN: 'Test CA' } } };
                }
                return cert;
            }),
        },
        headers: headers || {},
    };
}

/**
 * Build a mock request for header-based cert extraction.
 */
function headerReq(headers) {
    return {
        socket: {
            authorized: false,
            getPeerCertificate: jest.fn(() => null),
        },
        headers: headers || {},
    };
}

/**
 * Build a mock request that can fall back to socket.
 */
function fallbackReq(headers, authorized, cert) {
    return {
        socket: {
            authorized,
            getPeerCertificate: jest.fn(() => cert),
        },
        headers: headers || {},
    };
}

// Generate a real self-signed cert for header-based tests (selfsigned v5 is async)
const generated = await generate([{ name: 'commonName', value: 'generated-client' }], {
    keySize: 2048,
    days: 365,
});
const encodedPem = encodeURIComponent(generated.cert);

// Build a base64-der chain (same cert twice, Traefik-style comma-separated)
// This produces a cert with issuerCertificate for chain-stripping tests.
const pemLines = generated.cert.split('\n').filter(l => !l.startsWith('-----') && l.trim());
const base64Der = pemLines.join('');
const base64DerChain = base64Der + ',' + base64Der;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Strategy', () => {

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    describe('constructor', () => {
        it('should be named client-cert by default', () => {
            const strategy = new Strategy(() => {});
            expect(strategy.name).toBe('client-cert');
        });

        it('should allow overriding the name', () => {
            const strategy = new Strategy({ name: 'custom-cert' }, () => {});
            expect(strategy.name).toBe('custom-cert');
        });

        it('should require a verify function', () => {
            expect(() => new Strategy()).toThrow(TypeError);
            expect(() => new Strategy()).toThrow('passport-client-certificate-auth: verify callback is required');
            expect(() => new Strategy({})).toThrow(TypeError);
            expect(() => new Strategy({ passReqToCallback: true })).toThrow(TypeError);
        });

        it('should accept (verify) signature', () => {
            const fn = () => {};
            const strategy = new Strategy(fn);
            expect(strategy._verify).toBe(fn);
        });

        it('should accept (options, verify) signature', () => {
            const fn = () => {};
            const strategy = new Strategy({}, fn);
            expect(strategy._verify).toBe(fn);
        });

        it('should accept (undefined, verify) without crashing', () => {
            const fn = () => {};
            const strategy = new Strategy(undefined, fn);
            expect(strategy._verify).toBe(fn);
            expect(strategy.name).toBe('client-cert');
        });

        it('should accept (null, verify) without crashing', () => {
            const fn = () => {};
            const strategy = new Strategy(null, fn);
            expect(strategy._verify).toBe(fn);
            expect(strategy.name).toBe('client-cert');
        });

        it('should throw if verifyHeader is set without verifyValue', () => {
            expect(() => new Strategy({ verifyHeader: 'X-Verify' }, () => {}))
                .toThrow(/verifyHeader and verifyValue must both be provided/);
        });

        it('should throw if verifyValue is set without verifyHeader', () => {
            expect(() => new Strategy({ verifyValue: 'SUCCESS' }, () => {}))
                .toThrow(/verifyHeader and verifyValue must both be provided/);
        });

        it('should accept verifyHeader and verifyValue together', () => {
            expect(() => new Strategy({
                verifyHeader: 'X-Verify',
                verifyValue: 'SUCCESS',
            }, () => {})).not.toThrow();
        });
    });

    // -----------------------------------------------------------------------
    // Socket-based authentication
    // -----------------------------------------------------------------------

    describe('socket-based authentication', () => {
        let strategy;
        let failSpy, successSpy, errorSpy;

        beforeEach(() => {
            failSpy = jest.fn();
            successSpy = jest.fn();
            errorSpy = jest.fn();
        });

        function setup(verify, options) {
            strategy = new Strategy(options || {}, verify);
            strategy.fail = failSpy;
            strategy.success = successSpy;
            strategy.error = errorSpy;
        }

        it('should fail when socket is not authorized', () => {
            setup((cert, done) => done(null, {}));
            const req = dummyReq(false, null);

            strategy.authenticate(req);

            expect(failSpy).toHaveBeenCalledWith('Client certificate required', 401);
            expect(successSpy).not.toHaveBeenCalled();
        });

        it('should fail when socket has no authorized property', () => {
            setup((cert, done) => done(null, {}));
            const req = { socket: {}, headers: {} };

            strategy.authenticate(req);

            expect(failSpy).toHaveBeenCalledWith('Client certificate required', 401);
        });

        it('should fail when req.socket is missing entirely', () => {
            setup((cert, done) => done(null, {}));
            const req = { headers: {} };

            strategy.authenticate(req);

            expect(failSpy).toHaveBeenCalledWith('Client certificate required', 401);
        });

        it('should error when certificate is null', () => {
            setup((cert, done) => done(null, {}));
            const req = dummyReq(true, null);

            strategy.authenticate(req);

            expect(errorSpy).toHaveBeenCalled();
            expect(errorSpy.mock.calls[0][0].message).toMatch(/could not be retrieved/);
        });

        it('should error when certificate is empty object', () => {
            setup((cert, done) => done(null, {}));
            const req = dummyReq(true, {});

            strategy.authenticate(req);

            expect(errorSpy).toHaveBeenCalled();
        });

        it('should succeed when verify callback provides a user', () => {
            const user = { name: 'admin' };
            setup((cert, done) => done(null, user));
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(successSpy).toHaveBeenCalledWith(user, undefined);
            expect(failSpy).not.toHaveBeenCalled();
            expect(errorSpy).not.toHaveBeenCalled();
        });

        it('should pass info from verify callback to success', () => {
            const user = { name: 'admin' };
            const info = { message: 'authenticated via cert' };
            setup((cert, done) => done(null, user, info));
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(successSpy).toHaveBeenCalledWith(user, info);
        });

        it('should fail with default message when verify callback provides false', () => {
            setup((cert, done) => done(null, false));
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(failSpy).toHaveBeenCalledWith('Certificate rejected by verify callback', 401);
            expect(successSpy).not.toHaveBeenCalled();
        });

        it('should fail with info when verify provides false and info', () => {
            const info = { message: 'not allowed' };
            setup((cert, done) => done(null, false, info));
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(failSpy).toHaveBeenCalledWith(info, 401);
        });

        it('should error when verify callback provides an error', () => {
            const verifyErr = new Error('database error');
            setup((cert, done) => done(verifyErr));
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(errorSpy).toHaveBeenCalledWith(verifyErr);
            expect(successSpy).not.toHaveBeenCalled();
            expect(failSpy).not.toHaveBeenCalled();
        });

        it('should route sync verify exceptions to this.error()', () => {
            const verifyErr = new Error('sync kaboom');
            setup(() => { throw verifyErr; });
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(errorSpy).toHaveBeenCalledWith(verifyErr);
            expect(successSpy).not.toHaveBeenCalled();
            expect(failSpy).not.toHaveBeenCalled();
        });

        it('should ignore repeated done calls after first success', () => {
            setup((cert, doneCb) => {
                doneCb(null, { name: 'admin' });
                doneCb(null, { name: 'second-user' });
            });
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(successSpy).toHaveBeenCalledTimes(1);
            expect(successSpy).toHaveBeenCalledWith({ name: 'admin' }, undefined);
            expect(failSpy).not.toHaveBeenCalled();
            expect(errorSpy).not.toHaveBeenCalled();
        });

        it('should ignore sync throws that happen after done already completed', () => {
            const verifyErr = new Error('thrown after done');
            setup((cert, doneCb) => {
                doneCb(null, { name: 'admin' });
                throw verifyErr;
            });
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(successSpy).toHaveBeenCalledTimes(1);
            expect(successSpy).toHaveBeenCalledWith({ name: 'admin' }, undefined);
            expect(errorSpy).not.toHaveBeenCalled();
            expect(failSpy).not.toHaveBeenCalled();
        });

        it('should not treat truthy non-thenable verify return values as promises', (done) => {
            setup((cert, doneCb) => {
                setImmediate(() => doneCb(null, { name: 'admin' }));
                return { truthy: true };
            });
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            setImmediate(() => {
                expect(successSpy).toHaveBeenCalledTimes(1);
                expect(successSpy).toHaveBeenCalledWith({ name: 'admin' }, undefined);
                expect(errorSpy).not.toHaveBeenCalled();
                expect(failSpy).not.toHaveBeenCalled();
                done();
            });
        });

        it('should ignore done calls that happen after async rejection already failed auth', (done) => {
            const verifyErr = new Error('async failure first');
            setup((cert, doneCb) => {
                setImmediate(() => doneCb(null, { name: 'admin' }));
                return Promise.reject(verifyErr);
            });
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            setImmediate(() => {
                expect(errorSpy).toHaveBeenCalledTimes(1);
                expect(errorSpy).toHaveBeenCalledWith(verifyErr);
                expect(successSpy).not.toHaveBeenCalled();
                expect(failSpy).not.toHaveBeenCalled();
                done();
            });
        });

        it('should ignore done calls that happen after sync throw already failed auth', (done) => {
            const verifyErr = new Error('sync throw first');
            setup((cert, doneCb) => {
                setImmediate(() => doneCb(null, { name: 'admin' }));
                throw verifyErr;
            });
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            setImmediate(() => {
                expect(errorSpy).toHaveBeenCalledTimes(1);
                expect(errorSpy).toHaveBeenCalledWith(verifyErr);
                expect(successSpy).not.toHaveBeenCalled();
                expect(failSpy).not.toHaveBeenCalled();
                done();
            });
        });

        it('should route async verify rejections to this.error()', (done) => {
            const verifyErr = new Error('async kaboom');
            setup(async () => {
                await Promise.resolve();
                throw verifyErr;
            });
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            setImmediate(() => {
                expect(errorSpy).toHaveBeenCalledWith(verifyErr);
                expect(successSpy).not.toHaveBeenCalled();
                expect(failSpy).not.toHaveBeenCalled();
                done();
            });
        });

        it('should ignore async verify rejection after done callback already succeeded', (done) => {
            setup(async (cert, doneCb) => {
                doneCb(null, { name: 'admin' });
                throw new Error('late rejection');
            });
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            setImmediate(() => {
                expect(successSpy).toHaveBeenCalledWith({ name: 'admin' }, undefined);
                expect(errorSpy).not.toHaveBeenCalled();
                expect(failSpy).not.toHaveBeenCalled();
                done();
            });
        });

        it('should set req.clientCertificate before calling verify', () => {
            let capturedReqCert;
            setup((cert, done) => {
                capturedReqCert = cert;
                done(null, { name: 'admin' });
            });
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(req.clientCertificate).toBe(mockCert);
            expect(capturedReqCert).toBe(mockCert);
        });
    });

    // -----------------------------------------------------------------------
    // passReqToCallback
    // -----------------------------------------------------------------------

    describe('passReqToCallback', () => {
        it('should NOT pass req when passReqToCallback is false', () => {
            let verifyArgs;
            const strategy = new Strategy((cert, done) => {
                verifyArgs = [cert, done];
                done(null, {});
            });
            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            expect(verifyArgs).toHaveLength(2);
            expect(verifyArgs[0]).toBe(mockCert);
            expect(typeof verifyArgs[1]).toBe('function');
        });

        it('should pass req when passReqToCallback is true', () => {
            let verifyArgs;
            const strategy = new Strategy(
                { passReqToCallback: true },
                (req, cert, done) => {
                    verifyArgs = [req, cert, done];
                    done(null, {});
                }
            );
            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            expect(verifyArgs).toHaveLength(3);
            expect(verifyArgs[0]).toBe(req);
            expect(verifyArgs[1]).toBe(mockCert);
            expect(typeof verifyArgs[2]).toBe('function');
        });

        it('should treat non-boolean passReqToCallback values as false', () => {
            let verifyArgs;
            const strategy = new Strategy(
                { passReqToCallback: 'false' },
                (...args) => {
                    verifyArgs = args;
                    const done = args[args.length - 1];
                    done(null, {});
                }
            );
            strategy.success = jest.fn();
            strategy.fail = jest.fn();
            strategy.error = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            expect(verifyArgs).toHaveLength(2);
            expect(verifyArgs[0]).toBe(mockCert);
            expect(typeof verifyArgs[1]).toBe('function');
            expect(strategy.success).toHaveBeenCalled();
            expect(strategy.error).not.toHaveBeenCalled();
        });
    });

    // -----------------------------------------------------------------------
    // includeChain
    // -----------------------------------------------------------------------

    describe('includeChain', () => {
        it('should call getPeerCertificate(false) by default', () => {
            const strategy = new Strategy((cert, done) => done(null, {}));
            strategy.success = jest.fn();
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(req.socket.getPeerCertificate).toHaveBeenCalledWith(false);
        });

        it('should call getPeerCertificate(true) when includeChain is true', () => {
            const strategy = new Strategy({ includeChain: true }, (cert, done) => done(null, {}));
            strategy.success = jest.fn();
            const req = dummyReq(true, mockCert);

            strategy.authenticate(req);

            expect(req.socket.getPeerCertificate).toHaveBeenCalledWith(true);
        });
    });

    // -----------------------------------------------------------------------
    // Header-based authentication
    // -----------------------------------------------------------------------

    describe('header-based authentication', () => {
        let strategy;
        let failSpy, successSpy, errorSpy;

        beforeEach(() => {
            failSpy = jest.fn();
            successSpy = jest.fn();
            errorSpy = jest.fn();
        });

        function setup(verify, options) {
            strategy = new Strategy(options, verify);
            strategy.fail = failSpy;
            strategy.success = successSpy;
            strategy.error = errorSpy;
        }

        it('should extract certificate from header using preset', () => {
            let capturedCert;
            setup((cert, done) => {
                capturedCert = cert;
                done(null, { name: cert.subject.CN });
            }, {
                certificateSource: 'aws-alb',
            });

            const req = headerReq({
                'x-amzn-mtls-clientcert': encodedPem,
            });

            strategy.authenticate(req);

            expect(successSpy).toHaveBeenCalled();
            expect(capturedCert).toBeTruthy();
            expect(capturedCert.subject).toBeTruthy();
        });

        it('should fail when header is missing and no fallback', () => {
            setup((cert, done) => done(null, {}), {
                certificateSource: 'aws-alb',
            });

            const req = headerReq({});

            strategy.authenticate(req);

            expect(failSpy).toHaveBeenCalledWith(
                'Client certificate header missing or malformed',
                401
            );
        });

        it('should strip issuerCertificate from header certs when includeChain is false', () => {
            let capturedCert;
            setup((cert, done) => {
                capturedCert = cert;
                done(null, {});
            }, {
                certificateHeader: 'x-client-cert',
                headerEncoding: 'base64-der',
            });

            // Use base64-der chain which produces issuerCertificate
            const req = headerReq({
                'x-client-cert': base64DerChain,
            });

            strategy.authenticate(req);

            expect(successSpy).toHaveBeenCalled();
            expect(capturedCert.issuerCertificate).toBeUndefined();
        });

        it('should keep issuerCertificate when includeChain is true', () => {
            let capturedCert;
            setup((cert, done) => {
                capturedCert = cert;
                done(null, {});
            }, {
                certificateHeader: 'x-client-cert',
                headerEncoding: 'base64-der',
                includeChain: true,
            });

            const req = headerReq({
                'x-client-cert': base64DerChain,
            });

            strategy.authenticate(req);

            expect(successSpy).toHaveBeenCalled();
            expect(capturedCert.issuerCertificate).toBeTruthy();
        });

        it('should fallback to socket when header extraction fails and fallbackToSocket is true', () => {
            setup((cert, done) => done(null, { name: 'admin' }), {
                certificateSource: 'aws-alb',
                fallbackToSocket: true,
            });

            const req = fallbackReq({}, true, mockCert);

            strategy.authenticate(req);

            expect(successSpy).toHaveBeenCalled();
            expect(req.socket.getPeerCertificate).toHaveBeenCalled();
        });

        it('should fail on socket fallback when socket is not authorized', () => {
            setup((cert, done) => done(null, {}), {
                certificateSource: 'aws-alb',
                fallbackToSocket: true,
            });

            const req = fallbackReq({}, false, null);

            strategy.authenticate(req);

            expect(failSpy).toHaveBeenCalledWith('Client certificate required', 401);
        });
    });

    // -----------------------------------------------------------------------
    // verifyHeader / verifyValue
    // -----------------------------------------------------------------------

    describe('verifyHeader/verifyValue', () => {
        let strategy;
        let failSpy, successSpy, errorSpy;

        beforeEach(() => {
            failSpy = jest.fn();
            successSpy = jest.fn();
            errorSpy = jest.fn();
        });

        function setup(verify, options) {
            strategy = new Strategy(options, verify);
            strategy.fail = failSpy;
            strategy.success = successSpy;
            strategy.error = errorSpy;
        }

        it('should pass when verify header matches', () => {
            setup((cert, done) => done(null, { name: 'admin' }), {
                certificateSource: 'aws-alb',
                verifyHeader: 'X-SSL-Client-Verify',
                verifyValue: 'SUCCESS',
            });

            const req = headerReq({
                'x-ssl-client-verify': 'SUCCESS',
                'x-amzn-mtls-clientcert': encodedPem,
            });

            strategy.authenticate(req);

            expect(successSpy).toHaveBeenCalled();
        });

        it('should fail when verify header does not match', () => {
            setup((cert, done) => done(null, {}), {
                certificateSource: 'aws-alb',
                verifyHeader: 'X-SSL-Client-Verify',
                verifyValue: 'SUCCESS',
            });

            const req = headerReq({
                'x-ssl-client-verify': 'FAILED',
                'x-amzn-mtls-clientcert': encodedPem,
            });

            strategy.authenticate(req);

            expect(failSpy).toHaveBeenCalledWith('Certificate verification failed', 401);
            expect(successSpy).not.toHaveBeenCalled();
        });

        it('should fail when verify header is missing', () => {
            setup((cert, done) => done(null, {}), {
                certificateSource: 'aws-alb',
                verifyHeader: 'X-SSL-Client-Verify',
                verifyValue: 'SUCCESS',
            });

            const req = headerReq({
                'x-amzn-mtls-clientcert': encodedPem,
            });

            strategy.authenticate(req);

            expect(failSpy).toHaveBeenCalledWith('Certificate verification failed', 401);
        });

        it('should fail when verify header is an array', () => {
            setup((cert, done) => done(null, {}), {
                certificateSource: 'aws-alb',
                verifyHeader: 'X-SSL-Client-Verify',
                verifyValue: 'SUCCESS',
            });

            const req = headerReq({
                'x-ssl-client-verify': ['SUCCESS', 'SUCCESS'],
                'x-amzn-mtls-clientcert': encodedPem,
            });

            strategy.authenticate(req);

            expect(failSpy).toHaveBeenCalledWith('Certificate verification failed', 401);
        });
    });

    // -----------------------------------------------------------------------
    // Hooks
    // -----------------------------------------------------------------------

    describe('hooks', () => {
        const savedConsoleError = console.error;
        afterEach(() => {
            console.error = savedConsoleError;
        });

        it('should call onAuthenticated on success', (done) => {
            let hookArgs = null;
            const strategy = new Strategy({
                onAuthenticated: (cert, req) => { hookArgs = { cert, req }; },
            }, (cert, doneCb) => doneCb(null, { name: 'admin' }));

            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            setImmediate(() => {
                expect(hookArgs).toBeTruthy();
                expect(hookArgs.cert).toBe(mockCert);
                expect(hookArgs.req).toBe(req);
                done();
            });
        });

        it('should not call onRejected on success', (done) => {
            const onRejected = jest.fn();
            const strategy = new Strategy({
                onAuthenticated: jest.fn(),
                onRejected,
            }, (cert, doneCb) => doneCb(null, { name: 'admin' }));

            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            setImmediate(() => {
                expect(onRejected).not.toHaveBeenCalled();
                done();
            });
        });

        it('should call onRejected when verify returns false', (done) => {
            let hookArgs = null;
            const strategy = new Strategy({
                onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; },
            }, (cert, doneCb) => doneCb(null, false));

            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            setImmediate(() => {
                expect(hookArgs).toBeTruthy();
                expect(hookArgs.cert).toBe(mockCert);
                expect(hookArgs.reason).toBe('callback_returned_false');
                done();
            });
        });

        it('should call onRejected when socket is not authorized', (done) => {
            let hookArgs = null;
            const strategy = new Strategy({
                onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; },
            }, (cert, doneCb) => doneCb(null, {}));

            strategy.fail = jest.fn();
            strategy.success = jest.fn();

            const req = dummyReq(false, null);
            strategy.authenticate(req);

            setImmediate(() => {
                expect(hookArgs).toBeTruthy();
                expect(hookArgs.cert).toBeNull();
                expect(hookArgs.reason).toBe('socket_not_authorized');
                done();
            });
        });

        it('should call onRejected when header is missing with no fallback', (done) => {
            let hookArgs = null;
            const strategy = new Strategy({
                certificateSource: 'aws-alb',
                onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; },
            }, (cert, doneCb) => doneCb(null, {}));

            strategy.fail = jest.fn();
            strategy.success = jest.fn();

            const req = headerReq({});
            strategy.authenticate(req);

            setImmediate(() => {
                expect(hookArgs).toBeTruthy();
                expect(hookArgs.reason).toBe('header_missing_or_malformed');
                done();
            });
        });

        it('should call onRejected when verification header mismatches', (done) => {
            let hookArgs = null;
            const strategy = new Strategy({
                certificateSource: 'aws-alb',
                verifyHeader: 'X-SSL-Client-Verify',
                verifyValue: 'SUCCESS',
                onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; },
            }, (cert, doneCb) => doneCb(null, {}));

            strategy.fail = jest.fn();
            strategy.success = jest.fn();

            const req = headerReq({ 'x-ssl-client-verify': 'FAILED' });
            strategy.authenticate(req);

            setImmediate(() => {
                expect(hookArgs).toBeTruthy();
                expect(hookArgs.reason).toBe('verification_header_mismatch');
                done();
            });
        });

        it('should call onRejected when cert is not retrievable from socket', (done) => {
            let hookArgs = null;
            const strategy = new Strategy({
                onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; },
            }, (cert, doneCb) => doneCb(null, {}));

            strategy.error = jest.fn();
            strategy.fail = jest.fn();
            strategy.success = jest.fn();

            const req = dummyReq(true, {});
            strategy.authenticate(req);

            setImmediate(() => {
                expect(hookArgs).toBeTruthy();
                expect(hookArgs.reason).toBe('certificate_not_retrievable');
                done();
            });
        });

        it('should not throw when async hook rejects', (done) => {
            console.error = jest.fn();
            const strategy = new Strategy({
                onAuthenticated: async () => { throw new Error('async boom'); },
            }, (cert, doneCb) => doneCb(null, { name: 'admin' }));

            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            setImmediate(() => {
                expect(console.error).toHaveBeenCalledWith(
                    'passport-client-certificate-auth: hook error:',
                    expect.any(Error)
                );
                done();
            });
        });

        it('should not throw when sync hook throws', (done) => {
            console.error = jest.fn();
            const strategy = new Strategy({
                onAuthenticated: () => { throw new Error('sync boom'); },
            }, (cert, doneCb) => doneCb(null, { name: 'admin' }));

            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            setImmediate(() => {
                expect(console.error).toHaveBeenCalledWith(
                    'passport-client-certificate-auth: hook error:',
                    expect.any(Error)
                );
                done();
            });
        });

        it('should not block authentication when hooks are slow', () => {
            // Return a promise that never resolves (doesn't hold the event loop
            // since it has no pending I/O or timers)
            const strategy = new Strategy({
                onAuthenticated: () => new Promise(() => {}),
            }, (cert, doneCb) => doneCb(null, { name: 'admin' }));

            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            // success should be called synchronously, before the hook finishes
            expect(strategy.success).toHaveBeenCalled();
        });

        it('should silently ignore non-function hooks without logging errors', (done) => {
            console.error = jest.fn();
            const strategy = new Strategy({
                onAuthenticated: 'not a function',
                onRejected: 42,
            }, (cert, doneCb) => doneCb(null, { name: 'admin' }));

            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);

            // Should not throw
            expect(() => strategy.authenticate(req)).not.toThrow();
            expect(strategy.success).toHaveBeenCalled();

            // The guard should prevent any execution — no console.error from try/catch
            setImmediate(() => {
                expect(console.error).not.toHaveBeenCalled();
                done();
            });
        });

        it('should not log errors when sync hook succeeds with non-Promise return', (done) => {
            console.error = jest.fn();
            const strategy = new Strategy({
                onAuthenticated: () => 'sync return value',
            }, (cert, doneCb) => doneCb(null, { name: 'admin' }));

            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            setImmediate(() => {
                expect(console.error).not.toHaveBeenCalled();
                done();
            });
        });
    });

    // -----------------------------------------------------------------------
    // Drop-in compatibility with passport-client-cert
    // -----------------------------------------------------------------------

    describe('passport-client-cert compatibility', () => {
        // Ported from passport-client-cert test suite

        it('should be named client-cert', () => {
            const strategy = new Strategy(() => {});
            expect(strategy.name).toBe('client-cert');
        });

        it('should require a verify function', () => {
            expect(() => new Strategy()).toThrow();
            expect(() => new Strategy({})).toThrow();

            // should not throw
            const f = () => {};
            new Strategy(f);
            new Strategy({}, f);
        });

        it('should fail if the cert is not authorized', () => {
            const strategy = new Strategy((cert, done) => done(null, {}));
            strategy.fail = jest.fn();
            strategy.success = jest.fn();
            strategy.error = jest.fn();

            const req = dummyReq(false);
            strategy.authenticate(req);

            expect(strategy.fail).toHaveBeenCalled();
        });

        it('should fail if the cert is missing', () => {
            const strategy = new Strategy((cert, done) => done(null, {}));
            strategy.fail = jest.fn();
            strategy.success = jest.fn();
            strategy.error = jest.fn();

            const req = dummyReq(true, null);
            strategy.authenticate(req);

            // We return error (500) for this case, not fail (401) — cert was
            // authorized but unreadable. This is an intentional improvement
            // over passport-client-cert.
            expect(strategy.error).toHaveBeenCalled();
        });

        it('should fail if the cert is empty', () => {
            const strategy = new Strategy((cert, done) => done(null, {}));
            strategy.fail = jest.fn();
            strategy.success = jest.fn();
            strategy.error = jest.fn();

            const req = dummyReq(true, {});
            strategy.authenticate(req);

            expect(strategy.error).toHaveBeenCalled();
        });

        it('should pass the parsed cert to the verify callback', () => {
            let passedToVerify;
            const strategy = new Strategy((cert, _done) => {
                passedToVerify = cert;
            });
            strategy.fail = jest.fn();
            strategy.success = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            expect(passedToVerify).toBe(mockCert);
        });

        it('should succeed if the verify callback provided a user', () => {
            const strategy = new Strategy((cert, done) => done(null, {}));
            strategy.success = jest.fn();
            strategy.fail = jest.fn();
            strategy.error = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            expect(strategy.success).toHaveBeenCalled();
        });

        it('should fail if the verify callback provided false instead of a user', () => {
            const strategy = new Strategy((cert, done) => done(null, false));
            strategy.fail = jest.fn();
            strategy.success = jest.fn();
            strategy.error = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            expect(strategy.fail).toHaveBeenCalled();
        });

        it('should error if the verify callback provided an error', () => {
            const strategy = new Strategy((cert, done) => done(new Error('error from verify')));
            strategy.error = jest.fn();
            strategy.success = jest.fn();
            strategy.fail = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            expect(strategy.error).toHaveBeenCalled();
        });

        it('should pass the request object to the verify callback when directed', () => {
            let passedReq;
            const strategy = new Strategy(
                { passReqToCallback: true },
                (req, cert, done) => {
                    passedReq = req;
                    done(null, {});
                }
            );
            strategy.fail = jest.fn();
            strategy.success = jest.fn();

            const req = dummyReq(true, mockCert);
            strategy.authenticate(req);

            expect(strategy.fail).not.toHaveBeenCalled();
            expect(strategy.success).toHaveBeenCalled();
            expect(passedReq).toBe(req);
        });
    });
});
