# frozen_string_literal: true

module Identizer
  module Saml
    # The RSA key + self-signed certificate the IdP signs assertions with,
    # persisted under the config dir so metadata stays stable across restarts.
    class Keypair
      def self.load_or_generate(config_dir)
        key_path = File.join(config_dir, "saml_signing_key.pem")
        cert_path = File.join(config_dir, "saml_signing_cert.pem")

        if File.exist?(key_path) && File.exist?(cert_path)
          return new(OpenSSL::PKey::RSA.new(File.read(key_path)),
                     OpenSSL::X509::Certificate.new(File.read(cert_path)))
        end

        key = OpenSSL::PKey::RSA.new(2048)
        certificate = self_signed(key)
        FileUtils.mkdir_p(config_dir)
        File.write(key_path, key.to_pem)
        File.chmod(0o600, key_path)
        File.write(cert_path, certificate.to_pem)
        new(key, certificate)
      end

      def self.self_signed(key)
        name = OpenSSL::X509::Name.parse("/CN=identizer-saml")
        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = 1
        cert.subject = name
        cert.issuer = name
        cert.public_key = key.public_key
        cert.not_before = Time.now - 60
        cert.not_after = Time.now + (10 * 365 * 24 * 60 * 60)
        cert.sign(key, OpenSSL::Digest.new("SHA256"))
        cert
      end

      attr_reader :key, :certificate

      def initialize(key, certificate)
        @key = key
        @certificate = certificate
      end

      # Base64 DER, the form embedded in SAML metadata and <ds:X509Certificate>.
      def certificate_base64
        Base64.strict_encode64(@certificate.to_der)
      end
    end
  end
end
