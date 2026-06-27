# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-27

First release. A local identity provider for developing and testing auth/SSO
integrations.

### OIDC / OAuth2
- Authorization-code flow with PKCE (S256/plain), refresh-token grant (rotated,
  single-use), RP-initiated logout, `nonce` in the id_token, `scope` echo.
- Token introspection (RFC 7662) and revocation (RFC 7009, revokes the paired
  token). OIDC discovery + JWKS; HS256 (default) and RS256 signing.
- AWS Cognito hosted-UI + management-API emulation, Auth0 login + Management API
  (`/api/v2/clients`, `/api/v2/connections`) for app provisioning/deprovisioning.
- Okta-style `/oauth2/v1/*` aliases for fixed-path clients; `aud` is the client_id.
- Optional client registry enabling `redirect_uri` / post-logout allowlists.

### SAML 2.0
- Real IdP: signed Response + Assertion (XML-DSig / RSA-SHA256), optional
  EncryptedAssertion (AES-256-CBC + RSA-OAEP), metadata, SP- and IdP-initiated SSO.
- Attribute names default to Microsoft/WS-Fed claim URIs; fully configurable
  (`saml_attribute_names`). Optional ACS allowlist; deflate-bomb guards.

### LDAP
- Simple-bind authentication and subtree search (equality / presence / substring /
  `&` `|` `!`) over the same directory; implicit-TLS LDAPS and StartTLS.

### Directory & storage
- LDAP-flavoured user directory (`DirectoryEntry`) projected onto OIDC claims,
  with arbitrary custom attributes. Pluggable identity store (default JSON
  `ConfigStore`; optional `SqliteStore`).

### Operability & security
- Standalone HTTPS server + `identizer` CLI; mountable, `SCRIPT_NAME`-aware Rack
  app. Seeded demo user, quick-start banner, request logging, `/healthz`, custom
  domain (`--domain`).
- Thread-safe, TTL-enforced grant store; private keys written `0600`; uniform PKCE
  enforcement; registered JWT claims protected from directory-attribute forging.
- `nokogiri` (SAML) and `net-ldap` (LDAP) load lazily; `sqlite3` is optional.

[Unreleased]: https://github.com/alex-andreiev/identizer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alex-andreiev/identizer/releases/tag/v0.1.0
