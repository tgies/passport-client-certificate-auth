/*!
 * passport-client-certificate-auth - Passport.js strategy for client certificate authentication
 * Copyright (C) 2026 Tony Gies
 * @license MIT
 */

import PassportStrategy from 'passport-strategy';
import { extractClientCertificate } from 'client-certificate-auth/extractor';

/**
 * Safely call a hook function without blocking or throwing.
 * Deferred via queueMicrotask to ensure truly non-blocking behavior.
 * @param {Function|undefined} hook
 * @param {...any} args
 */
function safeCallHook(hook, ...args) {
    if (typeof hook !== 'function') {
        return;
    }
    queueMicrotask(() => {
        try {
            const result = hook(...args);
            if (result instanceof Promise) {
                result.catch(err => console.error('passport-client-certificate-auth: hook error:', err));
            }
        } catch (err) {
            console.error('passport-client-certificate-auth: hook error:', err);
        }
    });
}

/**
 * Passport strategy for TLS client certificate authentication.
 *
 * Supports both direct TLS socket certificates and reverse proxy header-based
 * certificate extraction via client-certificate-auth/extractor.
 *
 * @param {object} [options]
 * @param {string} [options.name='client-cert'] - Strategy name for passport.authenticate()
 * @param {boolean} [options.passReqToCallback=false] - Pass req as first arg to verify callback
 * @param {import('client-certificate-auth/parsers').CertificateSource} [options.certificateSource]
 * @param {string} [options.certificateHeader]
 * @param {import('client-certificate-auth/parsers').HeaderEncoding} [options.headerEncoding]
 * @param {boolean} [options.fallbackToSocket=false]
 * @param {boolean} [options.includeChain=false]
 * @param {string} [options.verifyHeader]
 * @param {string} [options.verifyValue]
 * @param {Function} [options.onAuthenticated]
 * @param {Function} [options.onRejected]
 * @param {Function} verify - Verify callback: (cert, done) or (req, cert, done)
 */
function Strategy(options, verify) {
    if (typeof options === 'function') {
        verify = options;
        options = {};
    }

    if (typeof verify !== 'function') {
        throw new TypeError('passport-client-certificate-auth: verify callback is required');
    }

    options = options || {};

    const {
        certificateSource,
        certificateHeader,
        headerEncoding,
        fallbackToSocket = false,
        includeChain = false,
        verifyHeader,
        verifyValue,
        onAuthenticated,
        onRejected,
    } = options;

    if ((verifyHeader && !verifyValue) || (!verifyHeader && verifyValue)) {
        throw new Error(
            'passport-client-certificate-auth: verifyHeader and verifyValue must both be provided together, or both omitted'
        );
    }

    PassportStrategy.call(this);

    this.name = options.name || 'client-cert';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback === true;
    this._certificateSource = certificateSource;
    this._certificateHeader = certificateHeader;
    this._headerEncoding = headerEncoding;
    this._fallbackToSocket = fallbackToSocket;
    this._includeChain = includeChain;
    this._verifyHeader = verifyHeader;
    this._verifyValue = verifyValue;
    this._onAuthenticated = onAuthenticated;
    this._onRejected = onRejected;
}

Object.setPrototypeOf(Strategy.prototype, PassportStrategy.prototype);

/**
 * Authenticate request based on client certificate.
 *
 * @param {object} req - Express/Connect request object
 */
Strategy.prototype.authenticate = function authenticate(req) {
    // Extract certificate from headers or socket
    const result = extractClientCertificate(req, {
        certificateSource: this._certificateSource,
        certificateHeader: this._certificateHeader,
        headerEncoding: this._headerEncoding,
        fallbackToSocket: this._fallbackToSocket,
        includeChain: this._includeChain,
        verifyHeader: this._verifyHeader,
        verifyValue: this._verifyValue,
    });

    if (!result.success) {
        safeCallHook(this._onRejected, null, req, result.reason);

        // Map reason codes to appropriate Passport error responses
        switch (result.reason) {
            case 'certificate_not_retrievable':
                return this.error(new Error(
                    'Client certificate was authenticated but certificate information could not be retrieved'
                ));
            case 'verification_header_mismatch':
                return this.fail('Certificate verification failed', 401);
            case 'header_missing_or_malformed':
                return this.fail('Client certificate header missing or malformed', 401);
            case 'socket_not_authorized':
                return this.fail('Client certificate required', 401);
        }
    }

    const cert = result.certificate;

    // Attach certificate to request for downstream access
    req.clientCertificate = cert;

    const self = this;
    let completed = false;

    /**
     * Passport verify done callback.
     * @param {Error|null} err
     * @param {object|false} user
     * @param {object} [info]
     */
    function done(err, user, info) {
        if (completed) {
            return undefined;
        }
        completed = true;

        if (err) {
            return self.error(err);
        }
        if (!user) {
            safeCallHook(self._onRejected, cert, req, 'callback_returned_false');
            return self.fail(info || 'Certificate rejected by verify callback', 401);
        }
        safeCallHook(self._onAuthenticated, cert, req);
        return self.success(user, info);
    }

    try {
        const verifyResult = this._passReqToCallback
            ? this._verify(req, cert, done)
            : this._verify(cert, done);

        // Defensive: async verify functions can reject after returning.
        // Route that to Passport's error handler instead of unhandled rejection.
        if (verifyResult && typeof verifyResult.then === 'function') {
            verifyResult.catch(ex => {
                if (completed) {
                    return;
                }
                completed = true;
                self.error(ex);
            });
        }
    } catch (ex) {
        if (completed) {
            return undefined;
        }
        completed = true;
        return self.error(ex);
    }
};

export default Strategy;
