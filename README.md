# Identizer

[![CI](https://github.com/alex-andreiev/identizer/actions/workflows/ci.yml/badge.svg)](https://github.com/alex-andreiev/identizer/actions/workflows/ci.yml)

A local identity provider for developing and testing auth/SSO integrations.

Identizer boots a local IdP that speaks **OIDC** and **OAuth2** and emulates an
**AWS Cognito / Auth0 SSO broker**, so the whole `popup → callback → login` round
trip can be configured and run locally without real tenants. Install it as a gem
and run it standalone, or mount it as a Rack app inside your test suite.

It is built from two halves:

- a **directory** of sign-in identities (the pluggable identity store — the "users"), and
- a **provider** that accepts auth requests, signs the user in, and hands the
  profile back over whichever protocol your app expects.

SSO is just one flow over that machinery; the same provider serves plain OIDC and
OAuth2 logins too.

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

### Identity store interface

Any object responding to this duck-typed interface can be a directory:

```
#emails              -> Array<String>   addresses the login form accepts
#identity_for(email) -> Identity | nil  resolve an address to an Identity
#replace_emails(...) -> (optional)       lets the dashboard edit the directory
```

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

| Purpose | Route |
|---|---|
| Dashboard / config | `GET /` |
| Login form | `GET /login`, `/authorize`, `/v1/authorize` |
| Cognito hosted-UI token | `POST /oauth2/token` |
| Auth0 token + profile | `POST /oauth/token`, `GET /userinfo` |
| OIDC token | `POST /v1/token` |
| OIDC discovery / JWKS | `GET /.well-known/openid-configuration`, `/.well-known/jwks.json` |
| SAML metadata | `GET /metadata` |
| Cognito management API | `POST /` with `x-amz-target` (point `COGNITO_ENDPOINT` here) |

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
