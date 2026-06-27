# frozen_string_literal: true

require "rexml/document"
require "zlib"

module Identizer
  module Handlers
    # A real SAML 2.0 IdP: signed metadata, an SSO endpoint that handles SP- and
    # IdP-initiated requests, and a signed-Response auto-POST back to the SP's
    # assertion consumer service. Signing is done by Identizer::Saml (nokogiri),
    # required lazily so it is only loaded when actually producing a Response.
    class Saml < Base
      EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      MAX_AUTHN_REQUEST = 100_000 # reject oversized SAMLRequest (deflate-bomb guard)

      def metadata(request)
        headers = {}
        headers["content-disposition"] = "attachment; filename=\"identizer-metadata.xml\"" if request.params["download"]
        xml(metadata_xml, headers: headers)
      end

      # SP-initiated (a SAMLRequest) or IdP-initiated (?acs=...): show the login form.
      def sso(request)
        context = authn_context(request)
        return json(400, { error: "no AssertionConsumerServiceURL" }) if context[:acs].to_s.empty?
        return saml_error("ACS not allowed: #{escape_html(context[:acs])}") unless config.acs_allowed?(context[:acs])

        login_form(request.script_name, context)
      end

      # Validate the login and POST a signed SAML Response back to the SP.
      def finish(request)
        email = request.params["email"].to_s.strip
        return saml_error("Invalid credentials") unless request.params["password"] == config.shared_password
        return saml_error("Unknown user: #{escape_html(email)}") unless store.emails.include?(email)

        acs = request.params["acs"].to_s
        return saml_error("ACS not allowed: #{escape_html(acs)}") unless config.acs_allowed?(acs)

        response = build_response(store.identity_for(email), acs, request)
        html(auto_post(acs, response, request.params["relay_state"].to_s))
      end

      private

      def build_response(identity, acs, request)
        require "identizer/saml"
        audience = present(request.params["audience"]) || acs
        Identizer::Saml::ResponseBuilder.new(config, config.saml_keypair).build_base64(
          identity: identity, acs_url: acs, audience: audience,
          in_response_to: present(request.params["in_response_to"])
        )
      end

      def authn_context(request)
        saml_request = request.params["SAMLRequest"].to_s
        relay_state = request.params["RelayState"].to_s
        base = { relay_state: relay_state }

        if saml_request.empty?
          base.merge(acs: request.params["acs"], audience: present(request.params["audience"]), in_response_to: nil)
        else
          parsed = parse_authn_request(saml_request, request.request_method)
          base.merge(acs: parsed[:acs] || request.params["acs"], audience: parsed[:issuer], in_response_to: parsed[:id])
        end
      end

      def parse_authn_request(value, method)
        return {} if value.bytesize > MAX_AUTHN_REQUEST

        raw = Base64.decode64(value)
        xml = method == "GET" ? inflate(raw) : raw
        document = REXML::Document.new(xml)
        root = document.root
        issuer = REXML::XPath.first(document, "//*[local-name()='Issuer']")&.text
        { acs: root&.attributes&.[]("AssertionConsumerServiceURL"), id: root&.attributes&.[]("ID"), issuer: issuer }
      rescue StandardError
        {}
      end

      def inflate(raw)
        out = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(raw)
        raise "SAMLRequest too large" if out.bytesize > 5_000_000

        out
      rescue StandardError
        raw
      end

      def present(value)
        value.to_s.empty? ? nil : value
      end

      def metadata_xml
        base = config.base_url
        <<~XML
          <?xml version="1.0" encoding="UTF-8"?>
          <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="#{base}/metadata">
            <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="false">
              <KeyDescriptor use="signing">
                <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                  <X509Data><X509Certificate>#{config.saml_keypair.certificate_base64}</X509Certificate></X509Data>
                </KeyInfo>
              </KeyDescriptor>
              <NameIDFormat>#{EMAIL_FORMAT}</NameIDFormat>
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="#{base}/saml/sso"/>
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="#{base}/saml/sso"/>
            </IDPSSODescriptor>
          </EntityDescriptor>
        XML
      end

      def login_form(prefix, context)
        render_login(
          title: "Identizer — SAML sign in", heading: "Identizer — SAML sign in",
          note: "Signing in to <code>#{escape_html(context[:acs])}</code>. Password for every identity: " \
                "<code>#{escape_html(config.shared_password)}</code>.",
          form_method: "post", action: "#{prefix}/saml/finish",
          hidden: [["acs", context[:acs]], ["audience", context[:audience]],
                   ["in_response_to", context[:in_response_to]], ["relay_state", context[:relay_state]]],
          config_link: ""
        )
      end

      def saml_error(message_html)
        notice_page("SAML error", message_html)
      end

      def auto_post(acs, saml_response, relay_state)
        relay = relay_state.empty? ? "" : %(<input type="hidden" name="RelayState" value="#{escape_html(relay_state)}">)
        <<~HTML
          <!doctype html><html><body onload="document.forms[0].submit()">
            <form method="post" action="#{escape_html(acs)}">
              <input type="hidden" name="SAMLResponse" value="#{escape_html(saml_response)}">
              #{relay}
              <noscript><button type="submit">Continue</button></noscript>
            </form>
          </body></html>
        HTML
      end
    end
  end
end
