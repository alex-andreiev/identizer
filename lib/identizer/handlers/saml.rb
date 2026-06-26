# frozen_string_literal: true

module Identizer
  module Handlers
    # Serves SAML IdP metadata. NOTE: this is cosmetic — the embedded certificate
    # is static and assertions are not actually signed/verified. It exists so a
    # SAML provider can be wired up (e.g. brokered through Cognito) end to end. A
    # real signed-assertion IdP is a roadmap item; see the README.
    class Saml < Base
      # A throwaway self-signed cert embedded in the metadata. Cosmetic only.
      METADATA_CERT =
        "MIIDDzCCAfegAwIBAgIUKlw5dRyRPxQJsUS8ybFh1SVuICAwDQYJKoZIhvcNAQELBQAwFzEVMBMGA1UEAww" \
        "Mc3NvLWVtdWxhdG9yMB4XDTI2MDYyNDEzNTUwNFoXDTM2MDYyMTEzNTUwNFowFzEVMBMGA1UEAwwMc3NvLW" \
        "VtdWxhdG9yMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj+2kiFzKLo1CWAaWCKINyzpcBUpFd" \
        "Z6NtPDyUMgqkk67z9WUHuW60gi3hnM0SlZCbCB0hyJM/78/qHo4zKkPVBLsCFpnyYKmBu/yHa4TohMeLTa4" \
        "5q8CBt2AndcxRXgZvAX75TSBkE5lmrWmFeOzr4lEmddBGXJDud92qRjcIRByXWbohN4xOlKNLuoYtd/vZPR" \
        "UdOe7h0qfiUHTuL6rr6HytFhPXeeFlmU0BUS/HaRUt8YsmRkAj+nfFpB7VYvlZ/TNzL6xuEZE0Gs9csyKl9" \
        "q3ju7QxtZwVbcvxekUFpL+Q/nvBdYYPtX/ItVv0c3ToooKcpzPf8BNH1elfLa2swIDAQABo1MwUTAdBgNVH" \
        "Q4EFgQUIDM3bZx5qvhzaGDYAq2H8gu9XAQwHwYDVR0jBBgwFoAUIDM3bZx5qvhzaGDYAq2H8gu9XAQwDwYD" \
        "VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAEpwLm6yMQ4QIap6yb5deMWCjHGGQoNKjsPXCCzb" \
        "gXXc+t2PDvqLLHc6sUrBxTUl7w+cfv0UwzkUA6guDUQwCKjQt5THZL4zmX7Du9OkT1WU9ooZjvmX687T14w" \
        "sHrj6TXObXUAlSODMuuhhOsbhNkAt6XrHcqJ5rK7EFSugHP2EnnBTYzkgBgXJ/g1WTfqJFu8QqxOwLzK6Ww" \
        "zNupqN69dTPXiGAtkU1wLQVUJfvfVilbdM7AeKxOH5Gi7cE1N5c3mdPj1EzVLWG8hNLaxN3zkSNNBsB8/cE" \
        "xblpUBugCS62HNCAFohmCQw3R2PcnNtfpTWfXajtctOZL/mj7AM/mw=="

      def metadata(request)
        headers = {}
        headers["content-disposition"] = "attachment; filename=\"identizer-metadata.xml\"" if request.params["download"]

        xml(metadata_xml, headers: headers)
      end

      private

      def metadata_xml
        base = config.base_url
        <<~XML
          <?xml version="1.0" encoding="UTF-8"?>
          <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="#{base}/metadata">
            <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
              <KeyDescriptor use="signing">
                <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                  <X509Data>
                    <X509Certificate>#{METADATA_CERT}</X509Certificate>
                  </X509Data>
                </KeyInfo>
              </KeyDescriptor>
              <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="#{base}/authorize"/>
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="#{base}/authorize"/>
            </IDPSSODescriptor>
          </EntityDescriptor>
        XML
      end
    end
  end
end
