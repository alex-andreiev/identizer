# frozen_string_literal: true

module Identizer
  # An LDAP-flavoured directory entry: an attribute bag (uid, cn, sn, givenName,
  # mail, ou, memberOf, ...) with a computed DN. This is the unit the directory
  # stores and the web admin edits. `to_identity` projects it onto the token-
  # facing Identity, mapping LDAP attributes to standard OIDC claims.
  class DirectoryEntry
    DEFAULT_BASE_DN = "dc=identizer,dc=local"
    DEFAULT_OU = "people"

    # LDAP attribute -> OIDC claim mapping for the token projection.
    CLAIM_MAP = {
      "givenName" => "given_name",
      "sn" => "family_name",
      "cn" => "name",
      "memberOf" => "groups",
      "uid" => "preferred_username"
    }.freeze

    # Attributes surfaced as editable fields in the web admin (in order).
    EDITABLE_ATTRIBUTES = %w[mail uid givenName sn cn ou memberOf].freeze

    attr_reader :attributes

    def initialize(attributes = {}, base_dn: DEFAULT_BASE_DN)
      @base_dn = base_dn
      @attributes = normalize(attributes)
      backfill!
    end

    def self.from(value, base_dn: DEFAULT_BASE_DN)
      return value if value.is_a?(DirectoryEntry)

      attributes = value.is_a?(Hash) ? value : { "mail" => value }
      new(attributes, base_dn: base_dn)
    end

    def [](key)
      @attributes[key.to_s]
    end

    def mail = self["mail"]
    def uid = self["uid"]
    def ou = self["ou"] || DEFAULT_OU
    def groups = Array(self["memberOf"]).reject { |group| group.to_s.empty? }

    def dn
      "uid=#{uid},ou=#{ou},#{@base_dn}"
    end

    # Token-facing projection: email + OIDC-mapped claims (+ dn).
    def to_identity
      claims = { "dn" => dn }
      @attributes.each do |key, value|
        next if %w[mail userPassword].include?(key)

        claims[CLAIM_MAP[key] || key] = value
      end
      Identity.new(email: mail, sub: dn, claims: claims)
    end

    def to_h
      @attributes
    end

    private

    def normalize(attributes)
      attributes.each_with_object({}) do |(key, value), acc|
        key = key.to_s
        key = "mail" if key == "email" # email is an alias for the mail attribute
        next if value.nil? || value == ""

        acc[key] = key == "memberOf" ? Array(value).reject { |group| group.to_s.empty? } : value
      end
    end

    def backfill!
      @attributes["mail"] = mail.to_s
      @attributes["uid"] ||= default_uid
      @attributes["cn"] ||= default_cn
    end

    def default_uid
      local = mail.to_s.split("@").first
      local.nil? || local.empty? ? "user" : local
    end

    def default_cn
      name = [self["givenName"], self["sn"]].compact.join(" ").strip
      name.empty? ? uid : name
    end
  end
end
