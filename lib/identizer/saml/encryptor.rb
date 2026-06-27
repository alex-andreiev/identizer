# frozen_string_literal: true

require "nokogiri"
require "openssl"
require "base64"

module Identizer
  module Saml
    # XML-Encryption of a (signed) SAML Assertion into an <EncryptedAssertion>:
    # AES-256-CBC for the assertion, RSA-OAEP key transport of the AES key under
    # the SP's certificate. Decryptable by standard SPs (validated with ruby-saml).
    class Encryptor
      XENC = "http://www.w3.org/2001/04/xmlenc#"
      AES256_CBC = "#{XENC}aes256-cbc".freeze
      RSA_OAEP = "#{XENC}rsa-oaep-mgf1p".freeze

      def initialize(certificate)
        @certificate = certificate
      end

      # Replaces `assertion` in its document with an <EncryptedAssertion> node.
      def encrypt!(assertion)
        document = assertion.document
        plaintext = assertion.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)

        cipher = OpenSSL::Cipher.new("aes-256-cbc").encrypt
        key = cipher.random_key
        iv = cipher.random_iv
        ciphertext = cipher.update(plaintext) + cipher.final

        encrypted = encrypted_assertion_node(
          document,
          cipher_value: Base64.strict_encode64(iv + ciphertext),
          encrypted_key: Base64.strict_encode64(transport_key(key)),
          certificate: Base64.strict_encode64(@certificate.to_der)
        )
        assertion.replace(encrypted)
        encrypted
      end

      private

      # RSA-OAEP (SHA-1 / MGF1, i.e. rsa-oaep-mgf1p) wrap of the AES key.
      def transport_key(key)
        @certificate.public_key.public_encrypt(key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      end

      def encrypted_assertion_node(document, cipher_value:, encrypted_key:, certificate:)
        fragment = [
          %(<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">),
          %(<xenc:EncryptedData xmlns:xenc="#{XENC}" Type="#{XENC}Element">),
          %(<xenc:EncryptionMethod Algorithm="#{AES256_CBC}"/>),
          %(<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>),
          %(<xenc:EncryptionMethod Algorithm="#{RSA_OAEP}"/>),
          %(<ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{certificate}</ds:X509Certificate>),
          %(</ds:X509Data></ds:KeyInfo>),
          %(<xenc:CipherData><xenc:CipherValue>#{encrypted_key}</xenc:CipherValue></xenc:CipherData>),
          %(</xenc:EncryptedKey></ds:KeyInfo>),
          %(<xenc:CipherData><xenc:CipherValue>#{cipher_value}</xenc:CipherValue></xenc:CipherData>),
          %(</xenc:EncryptedData></saml:EncryptedAssertion>)
        ].join
        document.parse(fragment).first
      end
    end
  end
end
