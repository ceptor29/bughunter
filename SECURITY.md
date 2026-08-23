# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Pre-release versions (0.x) receive security fixes on the latest release only.

## Reporting a vulnerability

Please do **not** open a public issue for security vulnerabilities.

Report privately by email to the maintainer at **ceptorboss@users.noreply.github.com**, or use GitHub's private vulnerability reporting if enabled on this repository.

Include as much of the following as possible:

- Affected version(s) and component
- Steps to reproduce
- Impact and any proof of concept

You should receive an acknowledgment within 3 business days. We will work with you to confirm, patch, and disclose the issue responsibly.

## Security notes for operators

- **Never commit auth tokens or manifests to git.** The `.gitignore` excludes `auth.yaml` and `manifest.yaml` by default.
- Authorization manifests contain scope boundaries. Treat them as sensitive configuration.
- The SQLite database and artifact store are excluded from git; keep them out of backups that are copied to untrusted storage.
- This is a pre-1.0 release. It has not been hardened for production and should not be used against targets without explicit authorization.
- Always use `--passive-only` or `safe` profile when testing against infrastructure you do not own.
- The web dashboard binds to localhost by default. Do not expose it to untrusted networks without authentication.

## Scope

This project is a security assessment tool. Users are responsible for:
- Obtaining proper authorization before scanning
- Complying with all applicable laws and regulations
- Using the tool ethically and responsibly
