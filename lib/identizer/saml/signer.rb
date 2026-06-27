# frozen_string_literal: true

require "nokogiri"

module Identizer
  module Saml
    # Enveloped XML-DSig signing (exclusive C14N, RSA-SHA256, SHA-256 digest) of a
    # SAML element. The Signature is inserted right after the element's Issuer, as
    # the SAML schema requires. Validated against ruby-saml in the specs.
    class Signer
      DS = "http://www.w3.org/2000/09/xmldsig#"
      EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
      ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
      SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
      RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

      def initialize(keypair)
        @keypair = keypair
      end

      # Signs `element` (a Nokogiri node with an "ID" attribute) in place.
      def sign!(element)
        reference_id = element["ID"]
        # Digest is over the element BEFORE the signature exists (enveloped transform).
        digest_value = base64(OpenSSL::Digest::SHA256.digest(canonicalize(element)))

        signature = build_signature(element.document, reference_id, digest_value)
        insert_signature(element, signature)

        # Canonicalize SignedInfo in its FINAL document context, then sign it — the
        # namespace context must match what the verifier sees.
        signed_info = signature.at_xpath("./ds:SignedInfo", "ds" => DS)
        signature_value = base64(@keypair.key.sign(OpenSSL::Digest.new("SHA256"), canonicalize(signed_info)))
        signature.at_xpath("./ds:SignatureValue", "ds" => DS).content = signature_value

        element
      end

      private

      def canonicalize(node)
        node.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
      end

      def base64(bytes)
        Base64.strict_encode64(bytes)
      end

      def insert_signature(element, signature)
        issuer = element.at_xpath("./*[local-name()='Issuer']")
        issuer ? issuer.after(signature) : element.prepend_child(signature)
      end

      def build_signature(document, reference_id, digest_value)
        node = Nokogiri::XML::Node.new("Signature", document)
        node.default_namespace = DS
        node.add_child(signed_info_xml(document, reference_id, digest_value))
        node.add_child(node_with(document, "SignatureValue", ""))
        node.add_child(key_info_xml(document))
        node
      end

      # Built as compact single-line fragments: any inter-tag whitespace would
      # become text nodes inside the canonicalized SignedInfo and break the digest.
      def signed_info_xml(document, reference_id, digest_value)
        fragment = [
          %(<SignedInfo xmlns="#{DS}">),
          %(<CanonicalizationMethod Algorithm="#{EXC_C14N}"/>),
          %(<SignatureMethod Algorithm="#{RSA_SHA256}"/>),
          %(<Reference URI="##{reference_id}"><Transforms>),
          %(<Transform Algorithm="#{ENVELOPED}"/>),
          %(<Transform Algorithm="#{EXC_C14N}"/></Transforms>),
          %(<DigestMethod Algorithm="#{SHA256}"/>),
          %(<DigestValue>#{digest_value}</DigestValue></Reference></SignedInfo>)
        ].join
        document.parse(fragment).first
      end

      def key_info_xml(document)
        fragment = [
          %(<KeyInfo xmlns="#{DS}"><X509Data>),
          %(<X509Certificate>#{@keypair.certificate_base64}</X509Certificate>),
          %(</X509Data></KeyInfo>)
        ].join
        document.parse(fragment).first
      end

      def node_with(document, name, content)
        node = Nokogiri::XML::Node.new(name, document)
        node.default_namespace = DS
        node.content = content
        node
      end
    end
  end
end
