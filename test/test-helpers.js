/*!
 * passport-client-certificate-auth - Test helpers
 * Copyright (C) 2026 Tony Gies
 * @license MIT
 */

import selfsigned from 'selfsigned';

/**
 * Generate a complete mTLS certificate chain: CA, server, and client.
 *
 * @returns {Promise<{ca: {cert, key}, server: {cert, key}, client: {cert, key}}>}
 */
export async function generateMtlsCertificates() {
    // Generate CA certificate
    const ca = await selfsigned.generate(
        [{ name: 'commonName', value: 'Test CA' }],
        {
            algorithm: 'sha256',
            keySize: 2048,
            notBeforeDate: new Date(Date.now() - 60_000),
            extensions: [
                { name: 'basicConstraints', cA: true, critical: true },
                { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
            ],
        }
    );

    // Generate server certificate signed by CA
    const server = await selfsigned.generate(
        [{ name: 'commonName', value: 'localhost' }],
        {
            algorithm: 'sha256',
            keySize: 2048,
            notBeforeDate: new Date(Date.now() - 60_000),
            ca: { key: ca.private, cert: ca.cert },
            extensions: [
                { name: 'basicConstraints', cA: false, critical: true },
                { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
                { name: 'extKeyUsage', serverAuth: true },
                {
                    name: 'subjectAltName',
                    altNames: [
                        { type: 2, value: 'localhost' },
                        { type: 7, ip: '127.0.0.1' },
                    ],
                },
            ],
        }
    );

    // Generate client certificate signed by CA
    const client = await selfsigned.generate(
        [{ name: 'commonName', value: 'Test Client' }],
        {
            algorithm: 'sha256',
            keySize: 2048,
            notBeforeDate: new Date(Date.now() - 60_000),
            ca: { key: ca.private, cert: ca.cert },
            extensions: [
                { name: 'basicConstraints', cA: false, critical: true },
                { name: 'keyUsage', digitalSignature: true, critical: true },
                { name: 'extKeyUsage', clientAuth: true },
            ],
        }
    );

    return {
        ca: { cert: ca.cert, key: ca.private },
        server: { cert: server.cert, key: server.private },
        client: { cert: client.cert, key: client.private },
    };
}

/**
 * Generate a self-signed client certificate (not signed by the test CA).
 *
 * @param {string} commonName
 * @returns {Promise<{cert: string, key: string}>}
 */
export async function generateClientCertificate(commonName = 'Untrusted Client') {
    const result = await selfsigned.generate(
        [{ name: 'commonName', value: commonName }],
        {
            algorithm: 'sha256',
            keySize: 2048,
            notBeforeDate: new Date(Date.now() - 60_000),
            extensions: [
                { name: 'basicConstraints', cA: false, critical: true },
                { name: 'keyUsage', digitalSignature: true, critical: true },
                { name: 'extKeyUsage', clientAuth: true },
            ],
        }
    );

    return { cert: result.cert, key: result.private };
}
