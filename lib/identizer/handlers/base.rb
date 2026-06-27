# frozen_string_literal: true

module Identizer
  module Handlers
    # Shared base for the protocol handlers. Each handler is constructed with a
    # context carrying the configuration, identity store, token minter and the
    # in-memory session map (opaque code/token -> Identity).
    class Base
      include Responses

      def initialize(context)
        @context = context
        @config = context.config
        @store = context.store
        @minter = context.minter
        @codes = context.codes
        @refresh_tokens = context.refresh_tokens
        @access_tokens = context.access_tokens
        @renderer = context.renderer
      end

      private

      attr_reader :config, :store, :minter, :codes, :refresh_tokens, :access_tokens, :renderer

      # Render a web-admin page through the shared layout.
      def page(template, request, nav:, title:, **locals)
        html(renderer.render(template, nav: nav, title: title, prefix: request.script_name, **locals))
      end

      def consume(code)
        codes.take(code)
      end

      # Consume a one-time authorization code and enforce PKCE when a challenge
      # was issued — uniformly, so a code can't be redeemed at a different token
      # endpoint to skip the check. Returns the Authorization, or nil if the code
      # is unknown or PKCE verification fails.
      def redeem_code(request)
        authorization = consume(code_param(request))
        return nil if authorization.nil?
        return nil unless authorization.pkce_valid?(request.params["code_verifier"])

        authorization
      end

      def code_param(request)
        if json_request?(request)
          parse_json(request)["code"]
        else
          request.params["code"]
        end
      end

      def bearer(request)
        request.get_header("HTTP_AUTHORIZATION").to_s.sub(/\ABearer\s+/i, "")
      end

      def parse_json(request)
        raw = request.body.read
        request.body.rewind
        safe_json(raw)
      end

      def json_request?(request)
        request.content_type.to_s.include?("json")
      end

      # Form params merged with a JSON body, so handlers work for either encoding.
      def merged_params(request)
        json = json_request?(request) ? parse_json(request) : {}
        request.params.merge(json)
      rescue StandardError
        request.params
      end

      def safe_json(raw)
        JSON.parse(raw.to_s)
      rescue JSON::ParserError
        {}
      end
    end
  end
end
