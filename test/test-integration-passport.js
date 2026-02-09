/*!
 * passport-client-certificate-auth - Integration tests with real Passport
 *
 * These tests verify the strategy works end-to-end through Passport's
 * authenticate() pipeline, not just with mocked success/fail/error.
 * Copyright (C) 2026 Tony Gies
 * @license MIT
 */

import passport from 'passport';
import Strategy from '../lib/strategy.js';
import { generate } from 'selfsigned';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const mockCert = {
    subject: { CN: 'test-client', O: 'Test Org' },
    issuer: { CN: 'Test CA' },
    fingerprint: 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01',
    serialNumber: '01:23:45:67',
    valid_from: 'Jan  1 00:00:00 2024 GMT',
    valid_to: 'Dec 31 23:59:59 2026 GMT',
};

function dummyReq(authorized, cert, headers) {
    return {
        socket: {
            authorized,
            getPeerCertificate: () => cert,
        },
        headers: headers || {},
        logIn: undefined,  // Passport will augment this
        logOut: undefined,
    };
}

function dummyRes() {
    const res = {
        statusCode: 200,
        _headers: {},
        _ended: false,
        _body: null,
        setHeader(name, value) { res._headers[name.toLowerCase()] = value; },
        getHeader(name) { return res._headers[name.toLowerCase()]; },
        end(body) { res._ended = true; res._body = body; },
    };
    return res;
}

// Generate a real self-signed cert for header-based tests (selfsigned v5 is async)
const generated = await generate([{ name: 'commonName', value: 'header-client' }], {
    keySize: 2048,
    days: 365,
});
const encodedPem = encodeURIComponent(generated.cert);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Passport integration', () => {
    // Use a fresh Passport instance per test to avoid cross-contamination
    let pp;

    beforeEach(() => {
        pp = new passport.Passport();
    });

    // -------------------------------------------------------------------
    // Strategy registration
    // -------------------------------------------------------------------

    describe('strategy registration', () => {
        it('should register with default name "client-cert"', () => {
            pp.use(new Strategy((cert, done) => done(null, {})));

            // Passport stores strategies by name; _strategy() returns the prototype
            expect(pp._strategy('client-cert')).toBeTruthy();
        });

        it('should register with custom name', () => {
            pp.use(new Strategy({ name: 'mtls' }, (cert, done) => done(null, {})));

            expect(pp._strategy('mtls')).toBeTruthy();
            expect(pp._strategy('client-cert')).toBeFalsy();
        });

        it('should allow name override via passport.use(name, strategy)', () => {
            pp.use('custom-name', new Strategy((cert, done) => done(null, {})));

            expect(pp._strategy('custom-name')).toBeTruthy();
        });
    });

    // -------------------------------------------------------------------
    // Custom callback API — passport.authenticate(name, callback)(req, res, next)
    // This is the cleanest way to test without session middleware.
    // -------------------------------------------------------------------

    describe('custom callback API', () => {
        it('should call back with user on successful authentication', (done) => {
            const user = { cn: 'test-client', role: 'admin' };

            pp.use(new Strategy((cert, done) => {
                done(null, user);
            }));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            pp.authenticate('client-cert', (err, resultUser) => {
                expect(err).toBeNull();
                expect(resultUser).toEqual(user);
                done();
            })(req, res, done);
        });

        it('should call back with false when verify rejects', (done) => {
            pp.use(new Strategy((cert, doneCb) => {
                doneCb(null, false);
            }));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            pp.authenticate('client-cert', (err, resultUser) => {
                expect(err).toBeNull();
                expect(resultUser).toBe(false);
                done();
            })(req, res, done);
        });

        it('should call back with error when verify errors', (done) => {
            const verifyError = new Error('database down');

            pp.use(new Strategy((cert, doneCb) => {
                doneCb(verifyError);
            }));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            pp.authenticate('client-cert', (err) => {
                expect(err).toBe(verifyError);
                done();
            })(req, res, done);
        });

        it('should call back with error when async verify rejects', (done) => {
            const verifyError = new Error('async failure');

            pp.use(new Strategy(async () => {
                await Promise.resolve();
                throw verifyError;
            }));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            pp.authenticate('client-cert', (err) => {
                expect(err).toBe(verifyError);
                done();
            })(req, res, done);
        });

        it('should call back with false when socket is not authorized', (done) => {
            pp.use(new Strategy((cert, doneCb) => {
                doneCb(null, { should: 'not reach' });
            }));

            const req = dummyReq(false, null);
            const res = dummyRes();

            pp.authenticate('client-cert', (err, resultUser, challenge) => {
                expect(err).toBeNull();
                expect(resultUser).toBe(false);
                expect(challenge).toBe('Client certificate required');
                done();
            })(req, res, done);
        });

        it('should call back with error when cert is not retrievable', (done) => {
            pp.use(new Strategy((cert, doneCb) => {
                doneCb(null, {});
            }));

            // authorized but empty cert
            const req = dummyReq(true, {});
            const res = dummyRes();

            pp.authenticate('client-cert', (err) => {
                expect(err).toBeInstanceOf(Error);
                expect(err.message).toMatch(/could not be retrieved/);
                done();
            })(req, res, done);
        });
    });

    // -------------------------------------------------------------------
    // Middleware-style — session: false to bypass session requirement
    // -------------------------------------------------------------------

    describe('middleware style (session: false)', () => {
        it('should set req.user and call next() on success', (done) => {
            const user = { cn: 'test-client' };

            pp.use(new Strategy((cert, doneCb) => {
                doneCb(null, user);
            }));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            const middleware = pp.authenticate('client-cert', { session: false });
            middleware(req, res, (err) => {
                expect(err).toBeUndefined();
                expect(req.user).toEqual(user);
                expect(req.clientCertificate).toBe(mockCert);
                done();
            });
        });

        it('should respond with 401 on failure', (done) => {
            pp.use(new Strategy((cert, doneCb) => {
                doneCb(null, false);
            }));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            const middleware = pp.authenticate('client-cert', { session: false });
            middleware(req, res, () => {
                done(new Error('next() should not be called on failure'));
            });

            // Passport calls res.end() on unauthenticated failures
            setImmediate(() => {
                expect(res.statusCode).toBe(401);
                expect(res._ended).toBe(true);
                done();
            });
        });

        it('should call next(err) on error', (done) => {
            pp.use(new Strategy((cert, doneCb) => {
                doneCb(new Error('internal error'));
            }));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            const middleware = pp.authenticate('client-cert', { session: false });
            middleware(req, res, (err) => {
                expect(err).toBeInstanceOf(Error);
                expect(err.message).toBe('internal error');
                done();
            });
        });
    });

    // -------------------------------------------------------------------
    // passReqToCallback through real Passport
    // -------------------------------------------------------------------

    describe('passReqToCallback through Passport', () => {
        it('should pass the request object to verify when configured', (done) => {
            let capturedReq;

            pp.use(new Strategy(
                { passReqToCallback: true },
                (req, cert, doneCb) => {
                    capturedReq = req;
                    doneCb(null, { cn: cert.subject.CN });
                }
            ));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            pp.authenticate('client-cert', (err, user) => {
                expect(err).toBeNull();
                expect(user).toEqual({ cn: 'test-client' });
                // Passport wraps via Object.create, so the req passed to
                // authenticate() is the same object verify receives
                expect(capturedReq).toBe(req);
                done();
            })(req, res, done);
        });
    });

    // -------------------------------------------------------------------
    // Header-based auth through real Passport
    // -------------------------------------------------------------------

    describe('header-based auth through Passport', () => {
        it('should extract cert from header and authenticate', (done) => {
            pp.use(new Strategy({
                certificateSource: 'aws-alb',
            }, (cert, doneCb) => {
                doneCb(null, { cn: cert.subject.CN });
            }));

            const req = dummyReq(false, null, {
                'x-amzn-mtls-clientcert': encodedPem,
            });
            const res = dummyRes();

            pp.authenticate('client-cert', (err, user) => {
                expect(err).toBeNull();
                expect(user).toBeTruthy();
                expect(user.cn).toBeTruthy();
                done();
            })(req, res, done);
        });

        it('should fail via Passport when header is missing', (done) => {
            pp.use(new Strategy({
                certificateSource: 'aws-alb',
            }, (cert, doneCb) => {
                doneCb(null, {});
            }));

            const req = dummyReq(false, null, {});
            const res = dummyRes();

            pp.authenticate('client-cert', (err, user, challenge) => {
                expect(err).toBeNull();
                expect(user).toBe(false);
                expect(challenge).toMatch(/missing or malformed/);
                done();
            })(req, res, done);
        });
    });

    // -------------------------------------------------------------------
    // Hooks fire through real Passport
    // -------------------------------------------------------------------

    describe('hooks through Passport', () => {
        const savedConsoleError = console.error;
        afterEach(() => {
            console.error = savedConsoleError;
        });

        it('should fire onAuthenticated hook on success', (done) => {
            let hookFired = false;

            pp.use(new Strategy({
                onAuthenticated: () => { hookFired = true; },
            }, (cert, doneCb) => {
                doneCb(null, { cn: cert.subject.CN });
            }));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            pp.authenticate('client-cert', (err, user) => {
                expect(err).toBeNull();
                expect(user).toBeTruthy();

                // Hook fires via queueMicrotask, check after setImmediate
                setImmediate(() => {
                    expect(hookFired).toBe(true);
                    done();
                });
            })(req, res, done);
        });

        it('should fire onRejected hook on failure', (done) => {
            let hookReason = null;

            pp.use(new Strategy({
                onRejected: (_cert, _req, reason) => { hookReason = reason; },
            }, (cert, doneCb) => {
                doneCb(null, false);
            }));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            pp.authenticate('client-cert', () => {
                setImmediate(() => {
                    expect(hookReason).toBe('callback_returned_false');
                    done();
                });
            })(req, res, done);
        });
    });

    // -------------------------------------------------------------------
    // assignProperty option (Passport feature)
    // -------------------------------------------------------------------

    describe('Passport assignProperty option', () => {
        it('should assign user to custom property instead of req.user', (done) => {
            const user = { cn: 'test-client' };

            pp.use(new Strategy((cert, doneCb) => {
                doneCb(null, user);
            }));

            const req = dummyReq(true, mockCert);
            const res = dummyRes();

            const middleware = pp.authenticate('client-cert', {
                assignProperty: 'account',
            });

            middleware(req, res, (err) => {
                expect(err).toBeUndefined();
                expect(req.account).toEqual(user);
                expect(req.user).toBeUndefined();
                done();
            });
        });
    });
});
