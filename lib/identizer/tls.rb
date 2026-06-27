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
      host = config.url_host
      name = OpenSSL::X509::Name.parse("/CN=#{host}")

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
      cert.add_extension(factory.create_extension("subjectAltName", subject_alt_names(host), false))
      cert.sign(key, OpenSSL::Digest.new("SHA256"))

      FileUtils.mkdir_p(config.config_dir)
      cert_path = File.join(config.config_dir, "cert.pem")
      key_path = File.join(config.config_dir, "key.pem")
      File.write(cert_path, cert.to_pem)
      File.write(key_path, key.to_pem)
      File.chmod(0o600, key_path)

      [cert, key, cert_path]
    end

    # Always covers localhost/127.0.0.1, plus a custom advertised host so HTTPS
    # works when the app reaches Identizer by that name (via /etc/hosts).
    def subject_alt_names(host)
      names = ["DNS:localhost", "IP:127.0.0.1"]
      names << "DNS:#{host}" unless host.nil? || host.empty? || host == "localhost"
      names.join(",")
    end
  end
end
