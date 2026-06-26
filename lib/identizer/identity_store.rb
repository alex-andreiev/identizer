# frozen_string_literal: true

module Identizer
  # An identity store is the "user directory" half of the provider. Any object
  # that responds to this duck-typed interface can be plugged in via
  # `config.identity_store`:
  #
  #   #emails              -> Array<String>  the addresses the login form accepts
  #   #identity_for(email) -> Identity|nil   resolve an address to an Identity
  #
  # Optionally, a store may expose `#replace_emails(Array<String>)` to let the
  # dashboard edit the directory in place (the default ConfigStore does).
  module IdentityStore
    # Default store: identities live in a JSON file the dashboard writes, with an
    # optional in-code seed used until the file has entries.
    class ConfigStore
      def initialize(path:, seed: [])
        @path = path
        @seed = Array(seed).map { |entry| Identity.from(entry) }
      end

      def identities
        persisted = read
        return persisted.map { |entry| Identity.from(entry) } unless persisted.empty?

        @seed
      end

      def emails
        identities.map(&:email)
      end

      def identity_for(email)
        email = email.to_s.strip
        return nil if email.empty?

        identities.find { |identity| identity.email == email } || Identity.from(email: email)
      end

      # Dashboard edit: replace the directory with plain emails (one per line).
      def replace_emails(emails)
        write(Array(emails).map { |email| { "email" => email } })
      end

      private

      def read
        data = JSON.parse(File.read(@path))
        data["identities"] || legacy(data) || []
      rescue StandardError
        []
      end

      # Accept the {"emails": [...]} shape too, so simple configs keep working.
      def legacy(data)
        return nil unless data["emails"].is_a?(Array)

        data["emails"].map { |email| { "email" => email } }
      end

      def write(identities)
        FileUtils.mkdir_p(File.dirname(@path))
        File.write(@path, JSON.generate("identities" => identities))
      end
    end
  end
end
