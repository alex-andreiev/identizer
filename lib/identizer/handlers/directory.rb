# frozen_string_literal: true

module Identizer
  module Handlers
    # CRUD over the LDAP-flavoured user directory. Requires a store exposing the
    # management interface (#entries, #upsert, #delete) — the default does.
    class Directory < Base
      # Reserved/standard names a custom attribute must not set — otherwise it
      # could overwrite a form field or forge a registered token claim.
      BLOCKED_ATTRIBUTES = (
        DirectoryEntry::EDITABLE_ATTRIBUTES +
        %w[iss aud exp iat nbf jti nonce sub email given_name family_name name groups preferred_username dn]
      ).map(&:downcase).freeze

      def index(request)
        editing = request.params["edit"]
        page("directory/index", request, nav: :directory, title: "Directory",
                                         entries: store.entries,
                                         entry: entry_for(editing),
                                         base_dn: config.ldap_base_dn)
      end

      def create(request)
        attributes = entry_params(request)
        # On rename (mail changed while editing), drop the old row so we don't
        # leave a duplicate behind.
        original = request.params["original_mail"].to_s
        store.delete(original) if !original.empty? && original != attributes["mail"]
        store.upsert(attributes)
        redirect("#{request.script_name}/directory")
      end

      def destroy(request)
        store.delete(request.params["mail"])
        redirect("#{request.script_name}/directory")
      end

      private

      def entry_for(mail)
        return DirectoryEntry.new(base_dn: config.ldap_base_dn) if mail.to_s.empty?

        store.entries.find { |entry| entry.mail == mail } ||
          DirectoryEntry.new(base_dn: config.ldap_base_dn)
      end

      def entry_params(request)
        params = request.params
        {
          "mail" => params["mail"], "uid" => params["uid"],
          "givenName" => params["givenName"], "sn" => params["sn"],
          "cn" => params["cn"], "ou" => params["ou"],
          "memberOf" => split_multi(params["memberOf"])
        }.merge(custom_attributes(params["custom_attributes"]))
      end

      def split_multi(value)
        value.to_s.split(/[\n,]/).map(&:strip).reject(&:empty?)
      end

      # Parse the free-form "name = value" (or "name: value") textarea into extra
      # attributes, so any provider-specific claim name can be set from the UI.
      def custom_attributes(text)
        text.to_s.lines.each_with_object({}) do |line, acc|
          key, value = line.split(/[:=]/, 2)
          next if key.nil? || value.nil?

          name = key.strip
          next if name.empty? || value.strip.empty? || BLOCKED_ATTRIBUTES.include?(name.downcase)

          acc[name] = value.strip
        end
      end
    end
  end
end
