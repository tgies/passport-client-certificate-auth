# passport-client-certificate-auth

Passport.js strategy for client certificate (mTLS) authentication, powered by [client-certificate-auth](https://github.com/tgies/client-certificate-auth).

Supports both direct TLS socket certificates and reverse proxy header-based certificate extraction (AWS ALB, Cloudflare, Envoy, Traefik, and custom configurations).

## Why this package?

[passport-client-cert](https://www.npmjs.com/package/passport-client-cert) has been abandoned since 2017 and only supports socket-based mTLS. This package is a modern, actively maintained replacement that adds:

- **Reverse proxy support** — Extract certificates from headers (AWS ALB, Cloudflare, Envoy, Traefik)
- **Verification header support** — Validate upstream proxy certificate verification status
- **Certificate chain support** — Optionally include the full issuer certificate chain
- **Validation helpers** — Use `client-certificate-auth/helpers` for common checks (CN, fingerprint, SAN, etc.)
- **Audit hooks** — Fire-and-forget `onAuthenticated`/`onRejected` callbacks for logging
- **TypeScript declarations** — Full type definitions included
- **Active maintenance** — Regular updates and security patches

## Install

```bash
npm install passport-client-certificate-auth
```

## Quick Start

### Drop-in replacement for passport-client-cert

```js
import passport from 'passport';
import { Strategy as ClientCertStrategy } from 'passport-client-certificate-auth';

passport.use(new ClientCertStrategy((cert, done) => {
    // cert is a Node.js PeerCertificate object
    const user = findUserByCN(cert.subject.CN);
    if (user) {
        return done(null, user);
    }
    return done(null, false);
}));

app.get('/protected',
    passport.authenticate('client-cert', { session: false }),
    (req, res) => {
        res.json({ user: req.user, cert: req.clientCertificate });
    }
);
```

### Accessing the certificate

After successful authentication, the client certificate is available on `req.clientCertificate` for downstream handlers. The certificate is attached before the verify callback runs, so it's also available when the verify callback rejects (`done(null, false)`). However, in early-fail paths where no certificate could be extracted (e.g., missing socket authorization, missing/malformed header, verification header mismatch), `req.clientCertificate` is not set.

### With request object (passReqToCallback)

```js
passport.use(new ClientCertStrategy(
    { passReqToCallback: true },
    (req, cert, done) => {
        // Access request properties alongside the certificate
        console.log(`${cert.subject.CN} requesting ${req.url}`);
        done(null, { cn: cert.subject.CN });
    }
));
```

## Reverse Proxy Support

When your app is behind a reverse proxy that terminates TLS, the proxy forwards the client certificate in an HTTP header. Use `certificateSource` to configure extraction automatically:

```js
// AWS Application Load Balancer
passport.use(new ClientCertStrategy({
    certificateSource: 'aws-alb',
}, (cert, done) => {
    done(null, { cn: cert.subject.CN });
}));

// Cloudflare
passport.use(new ClientCertStrategy({
    certificateSource: 'cloudflare',
}, (cert, done) => {
    done(null, { cn: cert.subject.CN });
}));
```

### Preset details

| Preset | Header | Encoding |
|--------|--------|----------|
| `aws-alb` | `X-Amzn-Mtls-Clientcert` | URL-encoded PEM (AWS variant) |
| `envoy` | `X-Forwarded-Client-Cert` | XFCC structured format |
| `cloudflare` | `Cf-Client-Cert-Der-Base64` | Base64-encoded DER |
| `traefik` | `X-Forwarded-Tls-Client-Cert` | Base64-encoded DER |

### Custom header configuration

```js
passport.use(new ClientCertStrategy({
    certificateHeader: 'X-SSL-Client-Cert',
    headerEncoding: 'url-pem',
}, (cert, done) => {
    done(null, { cn: cert.subject.CN });
}));
```

### Encoding formats

| Encoding | Description | Used By |
|----------|-------------|---------|
| `url-pem` | URL-encoded PEM certificate | nginx, HAProxy |
| `url-pem-aws` | URL-encoded PEM (AWS variant, `+` as safe char) | AWS ALB |
| `xfcc` | Envoy's structured `Key=Value;...` format | Envoy, Istio |
| `base64-der` | Base64-encoded DER certificate | Cloudflare, Traefik |
| `rfc9440` | RFC 9440 format: `:base64-der:` | Google Cloud LB |

### Verification header

Some proxies provide a separate header indicating whether the client certificate was verified:

```js
passport.use(new ClientCertStrategy({
    certificateSource: 'aws-alb',
    verifyHeader: 'X-SSL-Client-Verify',
    verifyValue: 'SUCCESS',
}, (cert, done) => {
    done(null, { cn: cert.subject.CN });
}));
```

### Fallback to socket

When header extraction fails, optionally fall back to direct TLS socket extraction:

```js
passport.use(new ClientCertStrategy({
    certificateSource: 'aws-alb',
    fallbackToSocket: true,
}, (cert, done) => {
    done(null, { cn: cert.subject.CN });
}));
```

### Security considerations

> **Important:** When using header-based authentication, your reverse proxy **must** strip any incoming certificate headers from external requests to prevent spoofing.

Configure your proxy to:
1. **Strip** the certificate header from incoming requests
2. **Set** the header only for authenticated mTLS connections
3. **Never** trust certificate headers from untrusted sources

Use `verifyHeader`/`verifyValue` as defense-in-depth to validate that the proxy actually verified the certificate.

## Using Validation Helpers

`client-certificate-auth` provides validation helpers that work with the Passport strategy:

```js
import { Strategy as ClientCertStrategy } from 'passport-client-certificate-auth';
import { allowCN, allowFingerprints, anyOf } from 'client-certificate-auth/helpers';

const isAllowed = anyOf(
    allowCN(['admin-service', 'monitoring']),
    allowFingerprints(['SHA256:AB:CD:EF:...'])
);

passport.use(new ClientCertStrategy((cert, done) => {
    isAllowed(cert)
        .then((allowed) => {
            if (allowed) {
                return done(null, { cn: cert.subject.CN });
            }
            return done(null, false);
        })
        .catch(done);
}));
```

> **Note:** The `/helpers` subpath export from `client-certificate-auth` is ESM-only. In CommonJS, use `const { allowCN } = await import('client-certificate-auth/helpers')`.

## Audit Hooks

```js
passport.use(new ClientCertStrategy({
    onAuthenticated: (cert, req) => {
        logger.info(`Authenticated: ${cert.subject.CN} at ${req.url}`);
    },
    onRejected: (cert, req, reason) => {
        logger.warn(`Rejected: ${cert?.subject?.CN || 'unknown'} - ${reason}`);
    },
}, (cert, done) => {
    done(null, { cn: cert.subject.CN });
}));
```

**Hook characteristics:**

- **Fire-and-forget**: Hooks don't block authentication. Async hooks run in the background.
- **Error-safe**: Hook errors are caught and logged to `console.error`, never affecting the request.
- **Cert may be null**: In `onRejected`, `cert` is `null` when certificate extraction failed (socket not authorized, header missing, etc.)

**Rejection reasons:**

| Reason | Description |
|--------|-------------|
| `socket_not_authorized` | TLS socket authorization failed |
| `certificate_not_retrievable` | Socket authorized but cert couldn't be read |
| `header_missing_or_malformed` | Certificate header absent or unparseable |
| `verification_header_mismatch` | Proxy verify header didn't match expected value |
| `callback_returned_false` | Verify callback called `done(null, false)` |

## Migration from passport-client-cert

1. Replace the dependency:
   ```bash
   npm uninstall passport-client-cert
   npm install passport-client-certificate-auth
   ```

2. Update your import:
   ```diff
   - const { Strategy } = require('passport-client-cert');
   + import { Strategy } from 'passport-client-certificate-auth';
   ```

3. Your verify callback works as-is — the `(cert, done)` and `(req, cert, done)` signatures are identical.

4. The default strategy name is `'client-cert'`, matching passport-client-cert exactly.

**Behavioral difference:** When `req.socket.authorized` is `true` but `getPeerCertificate()` returns `null` or an empty object, passport-client-cert calls `this.fail()` (401). This package calls `this.error()` (500) instead, since a certificate that was authorized but can't be read indicates a server-side issue, not a client authentication failure.

## API Reference

### `new Strategy([options], verify)`

| Option | Type | Default | Description |
|---|---|---|---|
| `name` | `string` | `'client-cert'` | Strategy name for `passport.authenticate()` |
| `passReqToCallback` | `boolean` | `false` | Pass `req` as first arg to verify callback |
| `certificateSource` | `string` | — | Preset: `'aws-alb'`, `'cloudflare'`, `'envoy'`, `'traefik'` |
| `certificateHeader` | `string` | — | Custom header name for certificate |
| `headerEncoding` | `string` | — | `'url-pem'`, `'url-pem-aws'`, `'xfcc'`, `'base64-der'`, `'rfc9440'` |
| `fallbackToSocket` | `boolean` | `false` | Fall back to socket if header extraction fails |
| `includeChain` | `boolean` | `false` | Include full certificate chain |
| `verifyHeader` | `string` | — | Header with proxy verification status |
| `verifyValue` | `string` | — | Expected verification status value |
| `onAuthenticated` | `function` | — | `(cert, req) => void` — fires on success |
| `onRejected` | `function` | — | `(cert, req, reason) => void` — fires on failure |

### Verify callback

```ts
// Without passReqToCallback
(cert: PeerCertificate, done: VerifyCallback) => void

// With passReqToCallback: true
(req: Request, cert: PeerCertificate, done: VerifyCallback) => void
```

The `done` callback follows Passport conventions:
- `done(null, user)` — success
- `done(null, false)` — authentication failed
- `done(null, false, info)` — failed with info message
- `done(error)` — internal error
- Verify callbacks are callback-style: always call `done` exactly once.

## CJS Usage

This package is ESM-only (because `client-certificate-auth/parsers` is ESM-only). From CommonJS:

```js
async function setup() {
    const { Strategy } = await import('passport-client-certificate-auth');
    passport.use(new Strategy((cert, done) => {
        done(null, { cn: cert.subject.CN });
    }));
}
```

## Requirements

- Node.js >= 20

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks, and PR expectations.

## Security

Please report vulnerabilities through private GitHub security advisories as described in [SECURITY.md](SECURITY.md).

## Changelog

Release notes and notable changes are documented in [CHANGELOG.md](CHANGELOG.md).

## License

MIT © Tony Gies
