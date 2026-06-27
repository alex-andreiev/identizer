# frozen_string_literal: true

module Identizer
  # An identity store is the "user directory" half of the provider. The provider
  # only needs this duck-typed read interface, so any backend (the default JSON
  # ConfigStore, a future SQLite adapter, an app's own DB) can be plugged in via
  # `config.identity_store`:
  #
  #   #emails              -> Array<String>  the addresses the login form accepts
  #   #identity_for(email) -> Identity|nil   resolve an address to an Identity
  #
  # For full management through the web admin a store also exposes the directory
  # interface: #entries, #upsert(attrs), #delete(email) (the default does).
  module IdentityStore
    # Default store: an LDAP-flavoured directory persisted to a JSON file the web
    # admin writes, seeded from in-code DirectoryEntry seeds until the file fills.
    class ConfigStore
      def initialize(path:, seed: [], base_dn: DirectoryEntry::DEFAULT_BASE_DN)
        @path = path
        @base_dn = base_dn
        @seed = Array(seed).map { |entry| DirectoryEntry.from(entry, base_dn: base_dn) }
      end

      def entries
        hashes = read
        return @seed if hashes.nil? # no usable file yet -> fall back to the seed

        hashes.map { |entry| DirectoryEntry.from(entry, base_dn: @base_dn) }
      end

      def emails
        entries.map(&:mail)
      end

      def identity_for(email)
        email = email.to_s.strip
        return nil if email.empty?

        entry = entries.find { |candidate| candidate.mail == email }
        (entry || DirectoryEntry.from({ "mail" => email }, base_dn: @base_dn)).to_identity
      end

      # Create or replace a directory entry, keyed by mail.
      def upsert(attrs)
        entry = DirectoryEntry.from(attrs, base_dn: @base_dn)
        remaining = current_hashes.reject { |hash| hash["mail"] == entry.mail }
        write(remaining + [entry.to_h])
        entry
      end

      def delete(email)
        email = email.to_s.strip
        write(current_hashes.reject { |hash| hash["mail"] == email })
      end

      private

      def current_hashes
        entries.map(&:to_h)
      end

      # Returns the persisted entry hashes (possibly empty), or nil when there is
      # no usable file yet — nil is what triggers the seed fallback.
      def read
        return nil unless File.exist?(@path)

        data = JSON.parse(File.read(@path))
        data["entries"] || data["identities"] || legacy(data) || []
      rescue StandardError
        nil
      end

      # Accept the {"emails": [...]} shape too, so simple configs keep working.
      def legacy(data)
        return nil unless data["emails"].is_a?(Array)

        data["emails"].map { |email| { "mail" => email } }
      end

      def write(entries)
        FileUtils.mkdir_p(File.dirname(@path))
        File.write(@path, JSON.generate("entries" => entries))
      end
    end
  end
end
