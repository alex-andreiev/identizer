# frozen_string_literal: true

module Identizer
  # A signed-in identity: a subject id, an email, and an arbitrary bag of
  # additional claims (given_name, family_name, groups, ...). `to_h` is what the
  # provider encodes into id_tokens and returns from /userinfo.
  class Identity
    attr_reader :sub, :email, :claims

    def initialize(email:, sub: nil, claims: {})
      @email = email.to_s
      @sub = (sub || "identizer|#{@email}").to_s
      @claims = stringify(claims)
    end

    # Coerce a Hash, String (email) or Identity into an Identity.
    def self.from(value)
      return value if value.is_a?(Identity)

      attrs = value.is_a?(Hash) ? value.transform_keys(&:to_sym) : { email: value }
      claims = attrs[:claims] || attrs.except(:email, :sub)
      new(email: attrs[:email], sub: attrs[:sub], claims: claims)
    end

    def to_h
      { "sub" => sub, "email" => email }.merge(claims)
    end

    def ==(other)
      other.is_a?(Identity) && other.to_h == to_h
    end

    private

    def stringify(hash)
      (hash || {}).each_with_object({}) { |(k, v), acc| acc[k.to_s] = v }
    end
  end
end
