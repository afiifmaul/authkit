# Architecture

> This document will be populated as the library is built.

## Overview

authkit is a modular authentication toolkit for Go backend applications.

## Package Structure

```
authkit/
├── bcrypt/      - Password hashing and verification
├── jwt/         - JWT access and refresh token management
├── otp/         - TOTP/MFA with Google Authenticator
├── middleware/   - HTTP authentication middleware
├── context/     - User claims context helpers
└── examples/    - Usage examples
```

## Design Principles

1. **Modular** — Each package is independent and can be used standalone.
2. **Idiomatic Go** — Follows Go conventions and best practices.
3. **Minimal Dependencies** — Only well-maintained, widely-used libraries.
4. **Production-Ready** — Proper error handling, testing, and documentation.
