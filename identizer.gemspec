# frozen_string_literal: true

require_relative "lib/identizer/version"

Gem::Specification.new do |spec|
  spec.name = "identizer"
  spec.version = Identizer::VERSION
  spec.authors = ["Alex Andreiev"]

  spec.summary = "A local identity provider for developing and testing auth/SSO integrations."
  spec.description = <<~DESC
    Identizer boots a local identity provider that emulates OIDC, OAuth2 and an
    AWS Cognito / Auth0 SSO broker, so the whole popup -> callback -> login round
    trip can be configured and run locally without real tenants. Installable as a
    gem, runnable standalone or mountable as a Rack app in tests.
  DESC
  spec.homepage = "https://github.com/alex-andreiev/identizer"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.glob("lib/**/*.rb") + Dir.glob("lib/**/*.erb") + Dir.glob("exe/*") +
               %w[README.md LICENSE.txt CHANGELOG.md]
  spec.bindir = "exe"
  spec.executables = ["identizer"]
  spec.require_paths = ["lib"]

  spec.add_dependency "jwt", ">= 2.0", "< 4"
  spec.add_dependency "net-ldap", "~> 0.19"   # required by the LDAP listener (loaded lazily)
  spec.add_dependency "nokogiri", "~> 1.15"   # required for SAML signing (loaded lazily)
  spec.add_dependency "rack", ">= 2.2", "< 4"
  spec.add_dependency "webrick", "~> 1.7"

  spec.add_development_dependency "rack-test", "~> 2.1"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "rubocop", "~> 1.65"
  spec.add_development_dependency "rubocop-rspec", "~> 3.0"
  spec.add_development_dependency "ruby-saml", "~> 1.17"
  spec.add_development_dependency "sqlite3", "~> 2.0"
end
