# frozen_string_literal: true

module Identizer
  module Ldap
    # Turns the directory into LDAP semantics: simple-bind authentication and
    # subtree search with attribute projection. Protocol-agnostic — the Server
    # handles BER; this handler only deals in DNs, attributes and result codes.
    class Handler
      SUCCESS = 0
      INVALID_CREDENTIALS = 49

      OBJECT_CLASSES = %w[top person organizationalPerson inetOrgPerson].freeze

      def initialize(config)
        @config = config
      end

      # Simple bind: anonymous (empty dn+password) succeeds; otherwise the DN must
      # resolve to a directory entry and the password must match the shared one.
      def bind(dn, password)
        return SUCCESS if dn.to_s.empty? && password.to_s.empty?
        return INVALID_CREDENTIALS unless password == @config.shared_password

        entry_for_dn(dn) ? SUCCESS : INVALID_CREDENTIALS
      end

      # Returns [{ dn:, attributes: }] for entries under `base` matching `filter`.
      def search(base, filter)
        base = base.to_s.downcase
        store.entries.filter_map do |entry|
          attributes = attributes_for(entry)
          next unless within_base?(entry, base)
          next unless Filter.match?(filter, attributes)

          { dn: entry.dn, attributes: attributes }
        end
      end

      private

      def store
        @config.identity_store
      end

      def entry_for_dn(dn)
        dn = dn.to_s.downcase
        store.entries.find { |entry| entry.dn.casecmp?(dn) }
      end

      def within_base?(entry, base)
        base.empty? || entry.dn.downcase.end_with?(base)
      end

      def attributes_for(entry)
        attributes = {
          "objectClass" => OBJECT_CLASSES,
          "uid" => [entry.uid], "cn" => [entry["cn"]], "mail" => [entry.mail],
          "ou" => [entry.ou], "givenName" => [entry["givenName"]], "sn" => [entry["sn"]],
          "memberOf" => entry.groups
        }
        attributes.transform_values { |values| Array(values).compact.map(&:to_s) }
                  .reject { |_, values| values.empty? }
      end
    end
  end
end
