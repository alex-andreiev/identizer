# frozen_string_literal: true

require "sqlite3"
require "json"

module Identizer
  module IdentityStore
    # Optional SQLite-backed directory. Same interface as ConfigStore, so it drops
    # in via `config.identity_store`. Requires the `sqlite3` gem (not a default
    # dependency) — add it to your Gemfile to use this adapter.
    #
    #   require "identizer/identity_store/sqlite_store"
    #   config.identity_store = Identizer::IdentityStore::SqliteStore.new(path: "dev.sqlite3")
    class SqliteStore
      def initialize(path:, base_dn: DirectoryEntry::DEFAULT_BASE_DN, seed: [])
        @base_dn = base_dn
        @db = SQLite3::Database.new(path.to_s)
        @db.execute("CREATE TABLE IF NOT EXISTS entries (mail TEXT PRIMARY KEY, data TEXT NOT NULL)")
        seed_if_empty(Array(seed))
      end

      def entries
        @db.execute("SELECT data FROM entries ORDER BY mail").map do |row|
          DirectoryEntry.from(JSON.parse(row[0]), base_dn: @base_dn)
        end
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

      def upsert(attrs)
        entry = DirectoryEntry.from(attrs, base_dn: @base_dn)
        @db.execute(<<~SQL, [entry.mail, JSON.generate(entry.to_h)])
          INSERT INTO entries (mail, data) VALUES (?, ?)
          ON CONFLICT(mail) DO UPDATE SET data = excluded.data
        SQL
        entry
      end

      def delete(email)
        @db.execute("DELETE FROM entries WHERE mail = ?", [email.to_s.strip])
      end

      def replace_emails(emails)
        @db.transaction do
          @db.execute("DELETE FROM entries")
          Array(emails).each { |email| upsert("mail" => email) }
        end
      end

      private

      def seed_if_empty(seed)
        return if seed.empty?
        return if @db.get_first_value("SELECT COUNT(*) FROM entries").to_i.positive?

        @db.transaction { seed.each { |entry| upsert(DirectoryEntry.from(entry, base_dn: @base_dn).to_h) } }
      end
    end
  end
end
