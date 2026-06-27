# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (follow-ups)
- OIDC token introspection (RFC 7662) at `/introspect` and token revocation
  (RFC 7009) at `/revoke` (plus the Okta `/oauth2/v1/*` aliases); advertised in
  discovery.
- SAML EncryptedAssertion: encrypt the signed assertion (AES-256-CBC + RSA-OAEP)
  under the SP's certificate (`saml_encrypt_assertion` + `saml_sp_certificate`),
  for SPs that require encryption. Decryptable by standard SPs (ruby-saml).
- Edit arbitrary custom attributes per directory entry in the web admin (so any
  provider-specific claim name can be set without code).
- The SAML Response is signed in addition to the Assertion (configurable via
  `saml_sign_response`).
- A `GET /healthz` endpoint reporting status + version.

### Hardening (code-review follow-ups)
- Tokens/codes now have enforced TTLs via a thread-safe `GrantStore` (codes 10m,
  access 1h, refresh 24h, all configurable) — expiry is testable and the maps no
  longer grow unbounded.
- Optional open-redirect guard: when `clients` are registered, `redirect_uri`
  must match a registered URI; an optional `saml_allowed_acs` allowlist guards
  the SAML ACS. Both lenient until configured.
- SAML `SAMLRequest` size + inflate guards (deflate-bomb protection).
- Auth0 management registry mutations are mutex-guarded.

### Security / correctness (code review)
- Enforce PKCE uniformly across all token endpoints (a code can no longer be
  redeemed at a different endpoint to skip the check).
- Auth0 flow now consumes the one-time code and returns a distinct access_token
  (no more unlimited replay / code-as-permanent-token).
- Private keys (RS256, SAML, TLS) are written with `0600` permissions.
- id_token `aud` is the requesting `client_id` (falls back to a constant).
- Friendly error for non-numeric port env vars; the 500 handler logs the
  backtrace to the server console instead of silently swallowing it.

### Fixed
- Renaming a directory entry's email no longer leaves a duplicate row.

### Added
- Initial release: a local identity provider for developing and testing auth/SSO
  integrations, extracted and decoupled from the tap-v3 SSO emulator.
- OIDC: PKCE (S256/plain), refresh-token grant (rotated), RP-initiated logout
  (`/v1/logout`), `nonce` in the id_token, `scope` echo, and an optional client
  registry. Discovery advertises these.
- OIDC and OAuth2 flows, AWS Cognito / Auth0 broker emulation.
- Auth0 Management API emulation: `client_credentials` token grant plus
  `/api/v2/clients` and `/api/v2/connections` (create/list/update/delete), so a
  brokering app can provision/deprovision applications like the Cognito stub.
- Real SAML 2.0 IdP: signed assertions (XML-DSig / RSA-SHA256), metadata, SP- and
  IdP-initiated SSO with a signed-Response auto-POST (`nokogiri`, loaded on demand).
- HS256 (default) and RS256 token signing with OIDC discovery and a published JWKS.
- LDAP-flavoured user directory (`DirectoryEntry`) projected onto OIDC claims.
- Pluggable identity store (default JSON-file `ConfigStore`); optional
  SQLite-backed `SqliteStore` adapter (`--sqlite`, needs the `sqlite3` gem).
- Web admin UI: Overview, Directory CRUD, Settings (persisted), bundled Docs.
- Standalone HTTPS server + `identizer` CLI, and a mountable, `SCRIPT_NAME`-aware
  Rack app.
- A seeded demo user on first run (`--no-demo` to skip) and a quick-start banner.
- Okta-style `/oauth2/v1/*` OAuth2 paths for fixed-path clients (e.g.
  `omniauth-okta`); the OIDC access token resolves at `/userinfo`.
- SAML attributes default to the Microsoft/WS-Fed claim URIs (configurable via
  `saml_attribute_names`), matching how real IdPs name them.
- Custom domain via `--domain` (cert SAN covers it; add it to `/etc/hosts`).
- Optional LDAP listener (`--ldap-port`): simple bind authentication and subtree
  search (equality / presence / substring / `&` `|` `!` filters) over the same
  directory, projecting entries to standard LDAP attributes.
- Optional LDAPS listener (`--ldaps-port`): implicit TLS reusing the HTTPS cert.

[Unreleased]: https://github.com/alex-andreiev/identizer/commits/main
