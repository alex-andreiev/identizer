# frozen_string_literal: true

module Identizer
  module Ldap
    # Matches an LDAP search filter (as parsed by Net::LDAP's BER reader) against
    # an entry's attribute hash. Operates directly on the BER structure, keyed by
    # ber_identifier, so it supports the compound filters Net::LDAP::Filter#match
    # does not (and / or / not), plus equality, presence and substrings.
    module Filter
      AND       = 0xa0
      OR        = 0xa1
      NOT       = 0xa2
      EQUALITY  = 0xa3
      SUBSTRING = 0xa4
      PRESENT   = 0x87

      module_function

      def match?(filter, attributes)
        case filter.ber_identifier
        when AND       then filter.all? { |sub| match?(sub, attributes) }
        when OR        then filter.any? { |sub| match?(sub, attributes) }
        when NOT       then !match?(filter.first, attributes)
        when EQUALITY  then equality?(filter, attributes)
        when SUBSTRING then substring?(filter, attributes)
        when PRESENT   then present?(filter, attributes)
        else true # unsupported filter types match everything (permissive for a test IdP)
        end
      end

      def equality?(filter, attributes)
        wanted = filter[1].to_s
        values(attributes, filter[0].to_s).any? { |value| value.casecmp?(wanted) }
      end

      def present?(filter, attributes)
        name = filter.to_s
        return true if name.casecmp?("objectclass")

        !values(attributes, name).empty?
      end

      def substring?(filter, attributes)
        parts = Array(filter[1]).map { |part| Regexp.escape(part.to_s) }
        return true if parts.empty?

        pattern = Regexp.new(parts.join(".*"), Regexp::IGNORECASE)
        values(attributes, filter[0].to_s).any? { |value| pattern.match?(value) }
      end

      # Case-insensitive attribute lookup -> array of string values.
      def values(attributes, name)
        key = attributes.keys.find { |candidate| candidate.to_s.casecmp?(name) }
        key ? Array(attributes[key]).map(&:to_s) : []
      end
    end
  end
end
