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

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.glob("lib/**/*.rb") + Dir.glob("exe/*") + %w[README.md LICENSE.txt]
  spec.bindir = "exe"
  spec.executables = ["identizer"]
  spec.require_paths = ["lib"]

  spec.add_dependency "jwt", ">= 2.0"
  spec.add_dependency "rack", ">= 2.2"
  spec.add_dependency "webrick", ">= 1.7"

  spec.add_development_dependency "rack-test", "~> 2.1"
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "rubocop", "~> 1.65"
  spec.add_development_dependency "rubocop-rspec", "~> 3.0"
end
