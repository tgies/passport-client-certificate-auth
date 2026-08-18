/*!
 * passport-client-certificate-auth - Tests
 * Copyright (C) 2026 Tony Gies
 * @license MIT
 */

import { jest } from '@jest/globals';

jest.unstable_mockModule('client-certificate-auth/extractor', () => ({
    extractClientCertificate: jest.fn(() => ({
        success: false,
        certificate: null,
        reason: 'reason_code_from_newer_core',
    })),
}));

const { default: Strategy } = await import('../lib/strategy.js');

describe('Strategy with unrecognized extraction reason', () => {
    it('fails closed without invoking the verify callback', (done) => {
        const verify = jest.fn((cert, doneCb) => doneCb(null, { name: 'user' }));
        const strategy = new Strategy(verify);

        strategy.success = jest.fn();
        strategy.error = jest.fn();
        strategy.fail = jest.fn();

        const req = { headers: {}, socket: { authorized: true } };
        strategy.authenticate(req);

        setImmediate(() => {
            expect(strategy.fail).toHaveBeenCalledWith('Client certificate authentication failed', 401);
            expect(verify).not.toHaveBeenCalled();
            expect(strategy.success).not.toHaveBeenCalled();
            expect(strategy.error).not.toHaveBeenCalled();
            expect(req.clientCertificate).toBeUndefined();
            done();
        });
    });

    it('reports the raw reason to onRejected', (done) => {
        let hookArgs = null;
        const strategy = new Strategy({
            onRejected: (cert, req, reason) => { hookArgs = { cert, req, reason }; },
        }, (cert, doneCb) => doneCb(null, false));

        strategy.fail = jest.fn();

        strategy.authenticate({ headers: {}, socket: { authorized: true } });

        setImmediate(() => {
            expect(hookArgs).toBeTruthy();
            expect(hookArgs.cert).toBeNull();
            expect(hookArgs.reason).toBe('reason_code_from_newer_core');
            done();
        });
    });
});
