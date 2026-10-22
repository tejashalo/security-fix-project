# Security policy

If you find a vulnerability in VibeGuard itself (for example a way to escape the ZIP extractor, read another user's results, or make the server run uploaded code), please open a private security advisory on GitHub (**Security → Report a vulnerability**) instead of a public issue.

VibeGuard's own protections:

- uploads are parsed, never executed; no packages are installed from uploads
- ZIP extraction blocks path traversal, symlinks, encrypted entries and oversized/bomb archives
- git commands run with the repository's config, hooks and alternates removed
- results are reachable only through a random 128-bit id and are deleted after 30 minutes
- strict Content-Security-Policy, security headers, rate limits and same-origin checks on the API
