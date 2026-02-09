# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this package, report it through GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/tgies/passport-client-certificate-auth/security) of this repository
2. Click **"Report a vulnerability"**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

### What to expect

- Confirmation that your report was received
- Regular updates on fix progress
- Credit in the advisory unless you prefer to remain anonymous
- CVE request for confirmed vulnerabilities when appropriate

## Security Best Practices

When using this strategy:

1. **Strip incoming certificate headers** at your reverse proxy to prevent spoofing
2. **Use `verifyHeader` and `verifyValue`** when authenticating from proxy headers
3. **Keep dependencies updated** and run `npm audit` regularly
4. **Validate certificate identity fields** in your verify callback, not just certificate presence
