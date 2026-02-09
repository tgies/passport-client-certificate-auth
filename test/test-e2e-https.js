/*!
 * passport-client-certificate-auth - End-to-end tests with real HTTPS/TLS
 *
 * These tests spin up a real HTTPS server with Passport middleware and make
 * real TLS requests with client certificates. This proves the full stack:
 * TLS handshake → socket.authorized → getPeerCertificate() → Strategy →
 * Passport → Express → HTTP response.
 *
 * Unlike unit/integration tests that mock socket.authorized and
 * getPeerCertificate(), these tests exercise the actual Node.js TLS layer.
 *
 * Copyright (C) 2026 Tony Gies
 * @license MIT
 */

import https from 'node:https';
import http from 'node:http';
import passport from 'passport';
import Strategy from '../lib/strategy.js';
import { generateMtlsCertificates, generateClientCertificate } from
    './test-helpers.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Make an HTTPS request and return { statusCode, body }.
 */
function request(url, options = {}) {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const reqOptions = {
            hostname: urlObj.hostname,
            port: urlObj.port,
            path: urlObj.pathname,
            method: 'GET',
            ...options,
        };

        const req = https.request(reqOptions, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
                } catch {
                    resolve({ statusCode: res.statusCode, body: data });
                }
            });
        });

        req.on('error', reject);
        req.setTimeout(5000, () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
        req.end();
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('E2E HTTPS with real TLS', () => {
    let certs;
    let server;
    let port;

    beforeAll(async () => {
        // Generate a full mTLS certificate chain
        certs = await generateMtlsCertificates();
    });

    afterEach((done) => {
        if (server) {
            server.close(done);
            server = null;
        } else {
            done();
        }
    });

    /**
     * Create an HTTPS server with Passport + our Strategy.
     * Uses custom callback so we control the JSON response on success,
     * fail, and error (Passport's default middleware sends plain text).
     * Returns a promise that resolves with the listening port.
     */
    function createServer(strategyOptions, verifyFn) {
        return new Promise((resolve) => {
            const pp = new passport.Passport();
            pp.use(new Strategy(strategyOptions, verifyFn));

            const handler = (req, res) => {
                pp.initialize()(req, res, () => {
                    pp.authenticate('client-cert', (err, user, info) => {
                        res.setHeader('Content-Type', 'application/json');
                        if (err) {
                            res.statusCode = err.status || 500;
                            res.end(JSON.stringify({
                                success: false,
                                error: err.message,
                            }));
                        } else if (!user) {
                            res.statusCode = 401;
                            res.end(JSON.stringify({
                                success: false,
                                error: typeof info === 'string' ? info : info?.message || 'Unauthorized',
                            }));
                        } else {
                            res.statusCode = 200;
                            res.end(JSON.stringify({
                                success: true,
                                user,
                                clientCertCN: req.clientCertificate?.subject?.CN,
                            }));
                        }
                    })(req, res, () => {});
                });
            };

            server = https.createServer({
                key: certs.server.key,
                cert: certs.server.cert,
                ca: [certs.ca.cert],
                requestCert: true,
                rejectUnauthorized: false,  // Let strategy handle rejection
            }, handler);

            server.listen(0, 'localhost', () => {
                port = server.address().port;
                resolve(port);
            });
        });
    }

    // -------------------------------------------------------------------
    // Successful authentication
    // -------------------------------------------------------------------

    it('should authenticate a valid client certificate', async () => {
        await createServer({}, (cert, done) => {
            done(null, { cn: cert.subject.CN, role: 'admin' });
        });

        const { statusCode, body } = await request(`https://localhost:${port}/`, {
            cert: certs.client.cert,
            key: certs.client.key,
            ca: certs.ca.cert,
        });

        expect(statusCode).toBe(200);
        expect(body.success).toBe(true);
        expect(body.user.cn).toBe('Test Client');
        expect(body.user.role).toBe('admin');
        expect(body.clientCertCN).toBe('Test Client');
    });

    // -------------------------------------------------------------------
    // Verify callback rejection
    // -------------------------------------------------------------------

    it('should return 401 when verify callback rejects', async () => {
        await createServer({}, (cert, done) => {
            done(null, false);
        });

        const { statusCode, body } = await request(`https://localhost:${port}/`, {
            cert: certs.client.cert,
            key: certs.client.key,
            ca: certs.ca.cert,
        });

        expect(statusCode).toBe(401);
        expect(body.success).toBe(false);
    });

    // -------------------------------------------------------------------
    // No client certificate
    // -------------------------------------------------------------------

    it('should return 401 when no client certificate is provided', async () => {
        await createServer({}, (cert, done) => {
            done(null, { cn: cert.subject.CN });
        });

        const { statusCode, body } = await request(`https://localhost:${port}/`, {
            ca: certs.ca.cert,
            // No cert/key
        });

        expect(statusCode).toBe(401);
        expect(body.success).toBe(false);
    });

    // -------------------------------------------------------------------
    // Untrusted certificate
    // -------------------------------------------------------------------

    it('should return 401 when client certificate is not trusted by server CA', async () => {
        const untrusted = await generateClientCertificate('Untrusted Client');

        await createServer({}, (cert, done) => {
            done(null, { cn: cert.subject.CN });
        });

        const { statusCode, body } = await request(`https://localhost:${port}/`, {
            cert: untrusted.cert,
            key: untrusted.key,
            ca: certs.ca.cert,
        });

        expect(statusCode).toBe(401);
        expect(body.success).toBe(false);
    });

    // -------------------------------------------------------------------
    // passReqToCallback
    // -------------------------------------------------------------------

    it('should pass real request object to verify with passReqToCallback', async () => {
        await createServer({ passReqToCallback: true }, (req, cert, done) => {
            // Verify we get real request properties
            done(null, {
                cn: cert.subject.CN,
                url: req.url,
                method: req.method,
            });
        });

        const { statusCode, body } = await request(`https://localhost:${port}/test-path`, {
            cert: certs.client.cert,
            key: certs.client.key,
            ca: certs.ca.cert,
        });

        expect(statusCode).toBe(200);
        expect(body.user.cn).toBe('Test Client');
        expect(body.user.url).toBe('/test-path');
        expect(body.user.method).toBe('GET');
    });

    // -------------------------------------------------------------------
    // includeChain
    // -------------------------------------------------------------------

    it('should include certificate chain when includeChain is true', async () => {
        let capturedCert;

        await createServer({ includeChain: true }, (cert, done) => {
            capturedCert = cert;
            done(null, { cn: cert.subject.CN });
        });

        const { statusCode } = await request(`https://localhost:${port}/`, {
            cert: certs.client.cert,
            key: certs.client.key,
            ca: certs.ca.cert,
        });

        expect(statusCode).toBe(200);
        // With includeChain: true, getPeerCertificate(true) returns issuerCertificate
        expect(capturedCert.issuerCertificate).toBeTruthy();
        expect(capturedCert.issuerCertificate.subject.CN).toBe('Test CA');
    });

    // -------------------------------------------------------------------
    // Verify callback error
    // -------------------------------------------------------------------

    it('should return 500 when verify callback errors', async () => {
        await createServer({}, (cert, done) => {
            done(new Error('database connection failed'));
        });

        const { statusCode, body } = await request(`https://localhost:${port}/`, {
            cert: certs.client.cert,
            key: certs.client.key,
            ca: certs.ca.cert,
        });

        expect(statusCode).toBe(500);
        expect(body.error).toBe('database connection failed');
    });

    // -------------------------------------------------------------------
    // Hooks fire with real TLS
    // -------------------------------------------------------------------

    it('should fire onAuthenticated hook with real TLS connection', async () => {
        let hookCert = null;

        await createServer({
            onAuthenticated: (cert) => { hookCert = cert; },
        }, (cert, done) => {
            done(null, { cn: cert.subject.CN });
        });

        const { statusCode } = await request(`https://localhost:${port}/`, {
            cert: certs.client.cert,
            key: certs.client.key,
            ca: certs.ca.cert,
        });

        expect(statusCode).toBe(200);
        // Wait for queueMicrotask-deferred hook
        await new Promise(resolve => setImmediate(resolve));
        expect(hookCert).toBeTruthy();
        expect(hookCert.subject.CN).toBe('Test Client');
    });

    it('should fire onRejected hook when real TLS client is unauthorized', async () => {
        let hookReason = null;

        await createServer({
            onRejected: (_cert, _req, reason) => { hookReason = reason; },
        }, (cert, done) => {
            done(null, { cn: cert.subject.CN });
        });

        const { statusCode } = await request(`https://localhost:${port}/`, {
            ca: certs.ca.cert,
            // No client cert
        });

        expect(statusCode).toBe(401);
        await new Promise(resolve => setImmediate(resolve));
        expect(hookReason).toBe('socket_not_authorized');
    });

    // -------------------------------------------------------------------
    // Header-based auth (simulated via HTTP, not proxied)
    // -------------------------------------------------------------------

    describe('header-based extraction (HTTP backend)', () => {
        let httpServer;
        let httpPort;

        afterEach((done) => {
            if (httpServer) {
                httpServer.close(done);
                httpServer = null;
            } else {
                done();
            }
        });

        /**
         * Create an HTTP (not HTTPS) server to test header-based extraction
         * without TLS. This simulates what happens behind a reverse proxy.
         * Uses custom callback for consistent JSON responses.
         */
        function createHttpServer(strategyOptions, verifyFn) {
            return new Promise((resolve) => {
                const pp = new passport.Passport();
                pp.use(new Strategy(strategyOptions, verifyFn));

                httpServer = http.createServer((req, res) => {
                    pp.initialize()(req, res, () => {
                        pp.authenticate('client-cert', (err, user, info) => {
                            res.setHeader('Content-Type', 'application/json');
                            if (err) {
                                res.statusCode = err.status || 500;
                                res.end(JSON.stringify({
                                    success: false,
                                    error: err.message,
                                }));
                            } else if (!user) {
                                res.statusCode = 401;
                                res.end(JSON.stringify({
                                    success: false,
                                    error: typeof info === 'string' ? info : info?.message || 'Unauthorized',
                                }));
                            } else {
                                res.statusCode = 200;
                                res.end(JSON.stringify({
                                    success: true,
                                    user,
                                    clientCertCN: req.clientCertificate?.subject?.CN,
                                }));
                            }
                        })(req, res, () => {});
                    });
                });

                httpServer.listen(0, '127.0.0.1', () => {
                    httpPort = httpServer.address().port;
                    resolve(httpPort);
                });
            });
        }

        it('should extract cert from header behind simulated proxy', async () => {
            // URL-encode the real client certificate PEM
            const encodedPem = encodeURIComponent(certs.client.cert);

            await createHttpServer({
                certificateHeader: 'x-ssl-client-cert',
                headerEncoding: 'url-pem',
            }, (cert, done) => {
                done(null, { cn: cert.subject.CN });
            });

            // Plain HTTP request with cert in header (simulating proxy)
            const { statusCode, body } = await new Promise((resolve, reject) => {
                const req = http.request({
                    hostname: '127.0.0.1',
                    port: httpPort,
                    path: '/',
                    method: 'GET',
                    headers: {
                        'x-ssl-client-cert': encodedPem,
                    },
                }, (res) => {
                    let data = '';
                    res.on('data', chunk => data += chunk);
                    res.on('end', () => {
                        resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
                    });
                });
                req.on('error', reject);
                req.end();
            });

            expect(statusCode).toBe(200);
            expect(body.success).toBe(true);
            expect(body.clientCertCN).toBe('Test Client');
        });

        it('should return 401 when cert header is missing', async () => {
            await createHttpServer({
                certificateHeader: 'x-ssl-client-cert',
                headerEncoding: 'url-pem',
            }, (cert, done) => {
                done(null, { cn: cert.subject.CN });
            });

            const { statusCode, body } = await new Promise((resolve, reject) => {
                const req = http.request({
                    hostname: '127.0.0.1',
                    port: httpPort,
                    path: '/',
                    method: 'GET',
                    // No cert header
                }, (res) => {
                    let data = '';
                    res.on('data', chunk => data += chunk);
                    res.on('end', () => {
                        resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
                    });
                });
                req.on('error', reject);
                req.end();
            });

            expect(statusCode).toBe(401);
            expect(body.success).toBe(false);
            expect(body.error).toMatch(/missing or malformed/);
        });
    });
});
