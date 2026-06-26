# frozen_string_literal: true

module Identizer
  # Resolves the TLS material the standalone server listens with. The login URLs
  # must be https (browser popup guards reject http), so we either use a provided
  # (e.g. mkcert-generated, locally-trusted) cert or fall back to a self-signed
  # one written under config_dir, which the app can trust via SSL_CERT_FILE.
  module TLS
    module_function

    # Returns [OpenSSL::X509::Certificate, OpenSSL::PKey::RSA, cert_path].
    def resolve(config)
      if config.tls_cert_path && config.tls_key_path
        cert = OpenSSL::X509::Certificate.new(File.read(config.tls_cert_path))
        key = OpenSSL::PKey::RSA.new(File.read(config.tls_key_path))
        return [cert, key, config.tls_cert_path]
      end

      generate_self_signed(config)
    end

    def generate_self_signed(config)
      key = OpenSSL::PKey::RSA.new(2048)
      name = OpenSSL::X509::Name.parse("/CN=localhost")

      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = name
      cert.issuer = name
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + (365 * 24 * 60 * 60)

      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = cert
      factory.issuer_certificate = cert
      cert.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
      cert.add_extension(factory.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1", false))
      cert.sign(key, OpenSSL::Digest.new("SHA256"))

      FileUtils.mkdir_p(config.config_dir)
      cert_path = File.join(config.config_dir, "cert.pem")
      File.write(cert_path, cert.to_pem)
      File.write(File.join(config.config_dir, "key.pem"), key.to_pem)

      [cert, key, cert_path]
    end
  end
end
