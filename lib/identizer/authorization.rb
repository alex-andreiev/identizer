# frozen_string_literal: true

module Identizer
  # What an issued code/refresh token stands for: the signed-in identity plus the
  # authorization-request parameters needed at token time (PKCE, scope, nonce).
  Authorization = Struct.new(:identity, :code_challenge, :code_challenge_method, :scope, :nonce,
                             keyword_init: true) do
    # RFC 7636 PKCE check. No challenge issued -> nothing to verify.
    def pkce_valid?(verifier)
      return true if code_challenge.to_s.empty?

      case code_challenge_method
      when "S256"
        digest = Digest::SHA256.digest(verifier.to_s)
        Base64.urlsafe_encode64(digest, padding: false) == code_challenge
      else # "plain" (or unspecified)
        verifier.to_s == code_challenge
      end
    end
  end
end
