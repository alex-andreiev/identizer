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
        @sessions = context.sessions
        @renderer = context.renderer
      end

      private

      attr_reader :config, :store, :minter, :sessions, :renderer

      # Render a web-admin page through the shared layout.
      def page(template, request, nav:, title:, **locals)
        html(renderer.render(template, nav: nav, title: title, prefix: request.script_name, **locals))
      end

      def consume(code)
        sessions.delete(code)
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

      def safe_json(raw)
        JSON.parse(raw.to_s)
      rescue JSON::ParserError
        {}
      end
    end
  end
end
