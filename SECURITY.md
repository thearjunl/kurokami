# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow responsible disclosure:

### How to Report

1. **DO NOT** open a public GitHub issue
2. Email security details to: arjunl2026@mca.ajce.in
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Critical issues within 30 days
- **Public Disclosure**: After fix is released

### Security Best Practices

When deploying KUROKAMI:

1. **Never commit secrets** to version control
2. **Use strong passwords** for database and API keys
3. **Enable encryption** for sensitive data
4. **Keep dependencies updated** regularly
5. **Run with least privilege** (non-root user)
6. **Enable rate limiting** in production
7. **Monitor audit logs** for suspicious activity
8. **Use HTTPS** for all external communications
9. **Implement authentication** for API access
10. **Regular security audits** of scan results

### Known Security Considerations

- **Subprocess Execution**: Modules execute external tools via subprocess. Input validation is critical.
- **Database Storage**: Findings contain sensitive information. Enable encryption in production.
- **Exploit Modules**: Controlled by `ALLOW_EXPLOITS` flag. Keep disabled unless explicitly needed.
- **Rate Limiting**: Prevents abuse. Configure appropriate limits for your environment.

### Security Features

- Input validation and sanitization
- Audit logging for all security-relevant events
- Rate limiting and resource quotas
- Timeout protection against DoS
- Non-root container execution
- Database encryption support
- API key authentication support

## Security Checklist for Production

- [ ] Change all default passwords
- [ ] Generate and set FERNET_KEY
- [ ] Generate and set API_KEY
- [ ] Enable WORKSPACE_ENCRYPTION
- [ ] Configure RATE_LIMIT_ENABLED=true
- [ ] Set ALLOW_EXPLOITS=false (unless needed)
- [ ] Use PostgreSQL instead of SQLite
- [ ] Enable HTTPS/TLS for API
- [ ] Configure firewall rules
- [ ] Set up automated backups
- [ ] Enable audit logging
- [ ] Review and restrict network access
- [ ] Implement monitoring and alerting
- [ ] Regular dependency updates
- [ ] Security scanning in CI/CD

## Vulnerability Disclosure Timeline

1. **Day 0**: Vulnerability reported
2. **Day 1-2**: Acknowledgment sent
3. **Day 3-7**: Initial assessment and triage
4. **Day 8-30**: Fix development and testing
5. **Day 31**: Security patch released
6. **Day 45**: Public disclosure (if appropriate)

## Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

<!-- Contributors will be listed here -->

## Contact

For security concerns: arjunl2026@mca.ajce.in
For general issues: https://github.com/thearjunl/kurokami/issues
