/*!
 * passport-client-certificate-auth - TypeScript declarations
 * Copyright (C) 2026 Tony Gies
 * @license MIT
 */

import type { Request } from 'express';
import type { PeerCertificate, DetailedPeerCertificate } from 'tls';
import type { CertificateSource, HeaderEncoding } from 'client-certificate-auth/parsers';

export type { CertificateSource, HeaderEncoding };

/**
 * Extended Express Request with clientCertificate property.
 */
export interface ClientCertRequest extends Request {
    /**
     * Client certificate attached by the strategy during authentication.
     * Available in verify callback and downstream middleware after successful auth.
     */
    clientCertificate?: PeerCertificate | DetailedPeerCertificate;
}

/**
 * Options for the ClientCert Passport strategy.
 */
export interface StrategyOptions {
    /**
     * Strategy name for passport.authenticate().
     * @default 'client-cert'
     */
    name?: string;

    /**
     * If true, the verify callback receives (req, cert, done) instead of (cert, done).
     * @default false
     */
    passReqToCallback?: boolean;

    /**
     * Use a preset configuration for a known reverse proxy.
     * Header-based certs are only checked if this or certificateHeader is set.
     */
    certificateSource?: CertificateSource;

    /**
     * Custom header name to read certificate from.
     * Overrides preset header name if also using certificateSource.
     */
    certificateHeader?: string;

    /**
     * How to decode the header value.
     * Required when using certificateHeader without certificateSource.
     */
    headerEncoding?: HeaderEncoding;

    /**
     * If header-based extraction is configured but fails, try socket.getPeerCertificate()
     * instead of failing authentication.
     * @default false
     */
    fallbackToSocket?: boolean;

    /**
     * If true, include the full certificate chain via cert.issuerCertificate.
     * @default false
     */
    includeChain?: boolean;

    /**
     * Header name containing certificate verification status from upstream proxy.
     * Must be used together with verifyValue.
     */
    verifyHeader?: string;

    /**
     * Expected value indicating successful certificate verification.
     * If verifyHeader is set, requests are rejected unless the header matches this value.
     */
    verifyValue?: string;

    /**
     * Called when a client is successfully authenticated.
     * Fire-and-forget: does not block authentication, errors are logged.
     */
    onAuthenticated?: (
        cert: PeerCertificate | DetailedPeerCertificate,
        req: ClientCertRequest
    ) => void | Promise<void>;

    /**
     * Called when authentication is rejected.
     * Fire-and-forget: does not block authentication, errors are logged.
     */
    onRejected?: (
        cert: PeerCertificate | DetailedPeerCertificate | null,
        req: ClientCertRequest,
        reason: string
    ) => void | Promise<void>;
}

/**
 * Options without passReqToCallback (or explicitly false).
 */
export interface StrategyOptionsWithoutReq extends StrategyOptions {
    passReqToCallback?: false;
}

/**
 * Options with passReqToCallback set to true.
 */
export interface StrategyOptionsWithReq extends StrategyOptions {
    passReqToCallback: true;
}

/**
 * Passport verify done callback.
 */
export type VerifyCallback = (
    error: Error | null,
    user?: object | false | null,
    info?: object | string
) => void;

/**
 * Verify function signature without request.
 */
export type VerifyFunction = (
    cert: PeerCertificate | DetailedPeerCertificate,
    done: VerifyCallback
) => void;

/**
 * Verify function signature with request (passReqToCallback: true).
 */
export type VerifyFunctionWithRequest = (
    req: ClientCertRequest,
    cert: PeerCertificate | DetailedPeerCertificate,
    done: VerifyCallback
) => void;

/**
 * Passport.js strategy for TLS client certificate authentication.
 *
 * Supports both direct TLS socket certificates and reverse proxy header-based
 * certificate extraction via client-certificate-auth/parsers.
 *
 * @example
 * // Socket-based authentication
 * passport.use(new Strategy((cert, done) => {
 *     if (cert.subject.CN === 'admin') {
 *         return done(null, { name: 'admin' });
 *     }
 *     return done(null, false);
 * }));
 *
 * @example
 * // Header-based with AWS ALB
 * passport.use(new Strategy({
 *     certificateSource: 'aws-alb'
 * }, (cert, done) => {
 *     return done(null, { cn: cert.subject.CN });
 * }));
 */
export declare class Strategy {
    name: string;

    constructor(verify: VerifyFunction);
    constructor(options: StrategyOptionsWithoutReq, verify: VerifyFunction);
    constructor(options: StrategyOptionsWithReq, verify: VerifyFunctionWithRequest);

    authenticate(req: ClientCertRequest): void;
}
