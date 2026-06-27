# frozen_string_literal: true

module Identizer
  module Handlers
    # Emulates the two AWS Cognito surfaces the original integration depends on:
    # the management API (used at provider-save time via the AWS SDK, reached by
    # pointing COGNITO_ENDPOINT here) and the hosted-UI token endpoint.
    class Cognito < Base
      # Provider-save time. The AWS SDK marks the operation with x-amz-target.
      def management_api(target, request)
        operation = target.split(".").last
        body = parse_json(request)
        name = body["ProviderName"] || body["ClientName"] || "identizer"

        amz_json(payload_for(operation, name, body))
      end

      # Cognito hosted-UI code exchange.
      def token(request)
        authorization = redeem_code(request)
        return json(400, { error: "invalid_grant" }) if authorization.nil?

        id_token = minter.id_token(authorization.identity, audience: authorization.client_id)
        json(200, { id_token: id_token, token_type: "Bearer" })
      end

      private

      def payload_for(operation, name, body)
        case operation
        when "CreateUserPoolClient"
          {
            "UserPoolClient" => {
              "ClientId" => SecureRandom.hex(13),
              "ClientSecret" => SecureRandom.hex(32),
              "ClientName" => body["ClientName"],
              "UserPoolId" => body["UserPoolId"]
            }
          }
        when "CreateIdentityProvider"
          { "IdentityProvider" => { "ProviderName" => name, "ProviderType" => body["ProviderType"] } }
        when "ListIdentityProviders"
          { "Providers" => [] }
        else
          {}
        end
      end
    end
  end
end
