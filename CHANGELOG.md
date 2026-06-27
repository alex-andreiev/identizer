# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release: a local identity provider for developing and testing auth/SSO
  integrations, extracted and decoupled from the tap-v3 SSO emulator.
- OIDC: PKCE (S256/plain), refresh-token grant (rotated), RP-initiated logout
  (`/v1/logout`), `nonce` in the id_token, `scope` echo, and an optional client
  registry. Discovery advertises these.
- OIDC and OAuth2 flows, AWS Cognito / Auth0 broker emulation, and cosmetic SAML
  metadata.
- HS256 (default) and RS256 token signing with OIDC discovery and a published JWKS.
- LDAP-flavoured user directory (`DirectoryEntry`) projected onto OIDC claims.
- Pluggable identity store (default JSON-file `ConfigStore`).
- Web admin UI: Overview, Directory CRUD, Settings (persisted), bundled Docs.
- Standalone HTTPS server + `identizer` CLI, and a mountable, `SCRIPT_NAME`-aware
  Rack app.
- Optional LDAP listener (`--ldap-port`): simple bind authentication and subtree
  search (equality / presence / substring / `&` `|` `!` filters) over the same
  directory, projecting entries to standard LDAP attributes.

[Unreleased]: https://github.com/alex-andreiev/identizer/commits/main
