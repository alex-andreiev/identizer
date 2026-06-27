# Identizer

[![CI](https://github.com/alex-andreiev/identizer/actions/workflows/ci.yml/badge.svg)](https://github.com/alex-andreiev/identizer/actions/workflows/ci.yml)

A local identity provider for developing and testing auth/SSO integrations.

**The problem it solves:** to test "Sign in with SSO", you normally need a real
Okta/Auth0/Azure/Cognito tenant, real metadata, real certificates. That's slow to
set up and impossible to script in CI. Identizer is a fake-but-real IdP you run
locally: point your app at it, sign in as a test user, done. No accounts, no cloud.

## Quick start (60 seconds)

```sh
gem install identizer
identizer                       # boots on https://localhost:9999
```

It prints exactly where to point your app. Open the dashboard at
`https://localhost:9999/` — a demo user (`demo@example.com`, password `password`)
is already there, so login works immediately. Then in your app's SSO settings:

- **OIDC / OpenID Connect** → issuer `https://localhost:9999` (the client reads
  everything else from `/.well-known/openid-configuration`).
- **SAML** → metadata `https://localhost:9999/metadata`.
- **OAuth2 / Auth0** → domain `localhost:9999`.

Trigger login in your app, sign in as the demo user, and you're testing the real
flow. (For browser/server TLS trust, see [TLS](#tls) — one `SSL_CERT_FILE` line.)

## Which protocol do I need?

If you're not sure how your app talks to its IdP, match the setting it asks for:

| Your app's SSO config mentions… | Use | Point it at |
|---|---|---|
| "Issuer URL", "discovery", "client ID/secret", `openid` | **OIDC** | `https://localhost:9999` |
| "Metadata URL/XML", "ACS", "SAML", "certificate" | **SAML** | `https://localhost:9999/metadata` |
| "Auth0 domain", `/authorize` + `/userinfo` | **OAuth2/Auth0** | `localhost:9999` |
| "Cognito", "user pool", `COGNITO_ENDPOINT` | **Cognito** | `COGNITO_ENDPOINT=https://localhost:9999` |
| "LDAP bind", `ldap://` | **LDAP** | `identizer --ldap-port 1389` |

## How it works (two halves)

- a **directory** of sign-in identities (the pluggable "users" store), and
- a **provider** that accepts auth requests, signs the user in, and hands the
  profile back over whichever protocol your app expects (OIDC, OAuth2, SAML, …).

## Why not an existing tool?

Generic OIDC mocks (e.g. `mock-oauth2-server`) are JVM/Docker, and SAML-only Ruby
gems (e.g. `saml_idp`) cover one protocol. Identizer is a single, zero-infra Ruby
gem that covers OIDC + OAuth2 + a Cognito/Auth0 **broker** with a pluggable user
directory — installable, mountable, and scriptable.

## Install

```ruby
# Gemfile (development/test)
gem "identizer", group: %i[development test]
```

```sh
bundle install
```

## Run standalone

```sh
bundle exec identizer --port 9999
# open https://localhost:9999/  (dashboard: identities + provider cheatsheet)
```

Common flags: `--port`, `--host`, `--url-host`, `--config-dir`, `--tls-cert`,
`--tls-key`, `--password`, `--rs256`. Anything not passed falls back to env vars
(`IDENTIZER_PORT`, `IDENTIZER_TLS_CERT/KEY`, `IDENTIZER_CONFIG_DIR`, …).

## Mount inside a Rack/Rails app

`Identizer::App` is a plain Rack app, so it works mounted at any path — internal
links honour `SCRIPT_NAME`.

```ruby
# config.ru
require "identizer"
run Identizer.app
```

```ruby
# Rails config/routes.rb (development only)
mount Identizer::App.new => "/idp" if Rails.env.development?
```

```ruby
# RSpec / rack-test
require "rack/test"

app = Identizer::App.new(
  Identizer::Configuration.new.tap do |c|
    c.config_dir = Dir.mktmpdir
    c.seed_identities = [{ email: "alice@example.com", claims: { given_name: "Alice" } }]
  end
)
```

## Configure

```ruby
Identizer.configure do |config|
  config.port = 9999
  config.shared_password = "password"          # type this to succeed; anything else exercises the error path
  config.signing = :rs256                       # :hs256 (default) or :rs256 + JWKS for clients that verify
  config.seed_identities = [
    { email: "alice@example.com", claims: { given_name: "Alice", family_name: "Doe" } }
  ]
  # config.identity_store = MyDbBackedStore.new  # plug in any object exposing #emails / #identity_for(email)
end
```

Other options (all have sane defaults): `code_ttl` / `access_token_ttl` /
`refresh_token_ttl` (grant lifetimes), `clients` (registry that enables
`redirect_uri` allowlisting), `saml_sign_response`, `saml_encrypt_assertion` +
`saml_sp_certificate`, `saml_allowed_acs`, `saml_attribute_names`, `ldap_port` /
`ldaps_port`, and `request_logging`. See `lib/identizer/configuration.rb`.

### Identity store interface

Any object responding to this duck-typed interface can be a directory:

```
#emails              -> Array<String>   addresses the login form accepts
#identity_for(email) -> Identity | nil  resolve an address to an Identity
```

For full management through the web admin, a store also exposes the directory
interface `#entries`, `#upsert(attrs)` and `#delete(email)` (the bundled
`ConfigStore` and `SqliteStore` do).

The default `Identizer::IdentityStore::ConfigStore` persists identities to a JSON
file the dashboard writes, seeded from `config.seed_identities`.

### SQLite backend (optional)

Prefer a database? Add `gem "sqlite3"` to your Gemfile and use the bundled adapter
— it implements the same directory interface, so the web admin and LDAP work
against it unchanged:

```sh
bundle exec identizer --sqlite ./dev.sqlite3
```

```ruby
require "identizer/identity_store/sqlite_store"
config.identity_store = Identizer::IdentityStore::SqliteStore.new(path: "dev.sqlite3")
```

`sqlite3` is not a default dependency — JSON files remain the zero-infra default.

## Endpoints

Most clients only need the issuer/metadata URL; the rest is discovered. Okta-style
`/oauth2/v1/*` aliases exist for the OIDC routes (authorize/token/userinfo/keys).

| Purpose | Route |
|---|---|
| Dashboard / config | `GET /` |
| Health | `GET /healthz` |
| Login form | `GET /login`, `/authorize`, `/v1/authorize` |
| Cognito hosted-UI token | `POST /oauth2/token` |
| Auth0 token + profile | `POST /oauth/token`, `GET /userinfo` |
| OIDC token / logout | `POST /v1/token`, `GET /v1/logout` |
| OIDC introspection / revocation | `POST /introspect`, `POST /revoke` |
| OIDC discovery / JWKS | `GET /.well-known/openid-configuration`, `/.well-known/jwks.json` |
| SAML metadata / SSO | `GET /metadata`, `GET|POST /saml/sso` |
| Cognito management API | `POST /` with `x-amz-target` (point `COGNITO_ENDPOINT` here) |
| Auth0 Management API | `POST/DELETE /api/v2/clients`, `/api/v2/connections` |

## LDAP listener (optional)

Apps that authenticate via LDAP can bind and search against the same directory.
It's off unless you ask for it:

```sh
bundle exec identizer --port 9999 --ldap-port 1389
# ldapsearch -x -H ldap://localhost:1389 -b dc=identizer,dc=local "(mail=alice@example.com)"
```

Simple bind (user DN + shared password, or anonymous) and subtree search with
equality / presence / substring / `&` `|` `!` filters. Entries project to
`uid, cn, sn, givenName, mail, ou, memberOf, objectClass`. Plain TCP + simple
bind — a development listener, not LDAPS.

## TLS

Login URLs must be `https` (browser popup guards reject `http`). Identizer uses a
provided cert (`--tls-cert/--tls-key`, ideally [mkcert](https://github.com/FiloSottile/mkcert)-generated
and locally trusted) or falls back to a self-signed cert written under
`config_dir`. For the app's server-to-server calls, trust it via
`export SSL_CERT_FILE=…/cert.pem`.

## SAML 2.0

A real SAML IdP: it issues **signed** assertions (XML-DSig, RSA-SHA256) verifiable
by standard SPs. Metadata at `/metadata`, SSO at `/saml/sso` (Redirect & POST
bindings), SP- and IdP-initiated. Signing uses `nokogiri`, loaded only when a
Response is produced. A development IdP — convenient, not hardened.

## Development

```sh
bin/setup            # install dependencies
bundle exec rake     # rspec + rubocop
bin/console          # an IRB session with identizer loaded
```

## License

MIT.
