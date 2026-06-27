# frozen_string_literal: true

module Identizer
  module Handlers
    # Emulates the slice of the Auth0 Management API a brokering app uses to
    # provision/deprovision SSO: creating and deleting applications (clients) and
    # SAML connections. Reached by pointing the Auth0 domain at Identizer; the
    # management bearer token (from the client_credentials grant) is accepted as-is.
    #
    # Created objects are kept in memory so list/delete behave consistently within
    # a running process.
    class Auth0Management < Base
      def initialize(context)
        super
        @clients = {}
        @connections = {}
        @mutex = Mutex.new # the WEBrick server is multithreaded
      end

      def create_client(request)
        client = parse_json(request).merge(
          "client_id" => SecureRandom.alphanumeric(32),
          "client_secret" => SecureRandom.alphanumeric(64)
        )
        @mutex.synchronize { @clients[client["client_id"]] = client }
        json(201, client)
      end

      def update_client(request, id)
        body = parse_json(request)
        updated = @mutex.synchronize { @clients[id] = (@clients[id] || { "client_id" => id }).merge(body) }
        json(200, updated)
      end

      def delete_client(_request, id)
        @mutex.synchronize { @clients.delete(id) }
        no_content
      end

      def list_clients(_request)
        json(200, @mutex.synchronize { @clients.values })
      end

      def create_connection(request)
        connection = parse_json(request).merge("id" => "con_#{SecureRandom.alphanumeric(24)}")
        @mutex.synchronize { @connections[connection["id"]] = connection }
        json(201, connection)
      end

      def update_connection(request, id)
        body = parse_json(request)
        updated = @mutex.synchronize { @connections[id] = (@connections[id] || { "id" => id }).merge(body) }
        json(200, updated)
      end

      def delete_connection(_request, id)
        @mutex.synchronize { @connections.delete(id) }
        no_content
      end

      def list_connections(_request)
        json(200, @mutex.synchronize { @connections.values })
      end
    end
  end
end
