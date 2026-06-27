# frozen_string_literal: true

require "nokogiri"
require "securerandom"

module Identizer
  module Saml
    # Builds a SAML 2.0 Response containing a signed Assertion for a signed-in
    # identity, ready to POST to the SP's assertion consumer service.
    class ResponseBuilder
      PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
      BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
      EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      BASIC_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
      URI_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
      PASSWORD_CONTEXT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
      VALIDITY = 300

      def initialize(config, keypair)
        @config = config
        @keypair = keypair
      end

      # Returns the signed Response XML string.
      def build(identity:, acs_url:, audience:, in_response_to: nil, now: Time.now)
        document = document_for(identity, acs_url, audience, in_response_to, now)
        signer = Signer.new(@keypair)
        signer.sign!(document.at_xpath("//saml:Assertion", "saml" => ASSERTION))
        encrypt_assertion(document) if encrypt?
        signer.sign!(document.root) if @config.saml_sign_response # sign the Response too
        document.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML |
                                   Nokogiri::XML::Node::SaveOptions::NO_DECLARATION)
      end

      def build_base64(**)
        Base64.strict_encode64(build(**))
      end

      private

      def encrypt?
        @config.saml_encrypt_assertion && @config.saml_sp_certificate
      end

      def encrypt_assertion(document)
        assertion = document.at_xpath("//saml:Assertion", "saml" => ASSERTION)
        Encryptor.new(@config.saml_sp_certificate).encrypt!(assertion)
      end

      def document_for(identity, acs_url, audience, in_response_to, now)
        response_id = "_#{SecureRandom.hex(16)}"
        assertion_id = "_#{SecureRandom.hex(16)}"

        builder = Nokogiri::XML::Builder.new do |xml|
          xml["samlp"].Response(response_attributes(response_id, acs_url, in_response_to, now)) do
            xml["saml"].Issuer(@config.issuer)
            xml["samlp"].Status { xml["samlp"].StatusCode(Value: SUCCESS) }
            assertion(xml, identity, assertion_id, acs_url, audience, in_response_to, now)
          end
        end
        builder.doc
      end

      def assertion(xml, identity, assertion_id, acs_url, audience, in_response_to, now)
        xml["saml"].Assertion(ID: assertion_id, Version: "2.0", IssueInstant: iso(now)) do
          xml["saml"].Issuer(@config.issuer)
          subject(xml, identity, acs_url, in_response_to, now)
          conditions(xml, audience, now)
          authn_statement(xml, assertion_id, now)
          attribute_statement(xml, identity)
        end
      end

      def subject(xml, identity, acs_url, in_response_to, now)
        xml["saml"].Subject do
          xml["saml"].NameID(identity.email, Format: EMAIL_FORMAT)
          xml["saml"].SubjectConfirmation(Method: BEARER) do
            xml["saml"].SubjectConfirmationData(confirmation_attributes(acs_url, in_response_to, now))
          end
        end
      end

      def conditions(xml, audience, now)
        xml["saml"].Conditions(NotBefore: iso(now - VALIDITY), NotOnOrAfter: iso(now + VALIDITY)) do
          xml["saml"].AudienceRestriction { xml["saml"].Audience(audience) }
        end
      end

      def authn_statement(xml, assertion_id, now)
        xml["saml"].AuthnStatement(AuthnInstant: iso(now), SessionIndex: assertion_id) do
          xml["saml"].AuthnContext { xml["saml"].AuthnContextClassRef(PASSWORD_CONTEXT) }
        end
      end

      def attribute_statement(xml, identity)
        names = @config.saml_attribute_names
        xml["saml"].AttributeStatement do
          identity.to_h.each do |claim, value|
            xml["saml"].Attribute(attribute_naming(claim, names)) do
              Array(value).each { |item| xml["saml"].AttributeValue(item.to_s) }
            end
          end
        end
      end

      # Map a claim to its SAML Attribute name/format, keeping the short claim
      # name as FriendlyName when a URI name is configured.
      def attribute_naming(claim, names)
        mapped = names[claim]
        return { Name: claim, NameFormat: BASIC_FORMAT } unless mapped

        { Name: mapped, FriendlyName: claim, NameFormat: URI_FORMAT }
      end

      def response_attributes(response_id, acs_url, in_response_to, now)
        attributes = {
          "xmlns:samlp" => PROTOCOL, "xmlns:saml" => ASSERTION,
          "ID" => response_id, "Version" => "2.0",
          "IssueInstant" => iso(now), "Destination" => acs_url
        }
        attributes["InResponseTo"] = in_response_to if in_response_to
        attributes
      end

      def confirmation_attributes(acs_url, in_response_to, now)
        attributes = { "NotOnOrAfter" => iso(now + VALIDITY), "Recipient" => acs_url }
        attributes["InResponseTo"] = in_response_to if in_response_to
        attributes
      end

      def iso(time)
        time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      end
    end
  end
end
