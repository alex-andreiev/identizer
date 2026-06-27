# frozen_string_literal: true

module Identizer
  module Ldap
    # A minimal LDAP v3 listener so apps that authenticate via LDAP can bind and
    # search against the directory. Speaks BER over a plain TCP socket using
    # Net::LDAP's codec. Supports simple bind, search (with the filters in
    # Identizer::Ldap::Filter) and unbind — enough to develop LDAP auth locally.
    class Server
      # protocolOp application tags (request side).
      BIND_REQUEST = 0x60
      SEARCH_REQUEST = 0x63
      UNBIND_REQUEST = 0x42

      # protocolOp application tags (response side).
      BIND_RESPONSE = 1
      SEARCH_ENTRY = 4
      SEARCH_DONE = 5

      PROTOCOL_ERROR = 2

      def initialize(config, host: nil, port: nil)
        @config = config
        @host = host || config.ldap_host || config.host
        @port = port || config.ldap_port || 1389
        @handler = Handler.new(config)
      end

      attr_reader :host, :port

      def start
        @socket = TCPServer.new(@host, @port)
        @running = true
        accept_loop
      end

      def stop
        @running = false
        @socket&.close
      rescue IOError
        nil
      end

      private

      def accept_loop
        while @running
          client = accept
          break unless client

          Thread.new(client) { |connection| serve(connection) }
        end
      end

      def accept
        @socket.accept
      rescue IOError, Errno::EBADF
        nil
      end

      def serve(connection)
        while (pdu = connection.read_ber(Net::LDAP::AsnSyntax))
          message_id = pdu[0]
          operation = pdu[1]
          break if dispatch(connection, message_id, operation) == :close
        end
      rescue StandardError
        nil
      ensure
        connection.close unless connection.closed?
      end

      def dispatch(connection, message_id, operation)
        case operation.ber_identifier
        when BIND_REQUEST then handle_bind(connection, message_id, operation)
        when SEARCH_REQUEST then handle_search(connection, message_id, operation)
        when UNBIND_REQUEST then :close
        else write(connection, message_id, result(PROTOCOL_ERROR, SEARCH_DONE))
        end
      end

      def handle_bind(connection, message_id, operation)
        code = @handler.bind(operation[1].to_s, operation[2].to_s)
        write(connection, message_id, result(code, BIND_RESPONSE))
      end

      def handle_search(connection, message_id, operation)
        base = operation[0].to_s
        filter = operation[6]
        @handler.search(base, filter).each do |entry|
          write(connection, message_id, search_entry(entry))
        end
        write(connection, message_id, result(Handler::SUCCESS, SEARCH_DONE))
      end

      def search_entry(entry)
        attributes = entry[:attributes].map do |name, values|
          [name.to_ber, values.map(&:to_ber).to_ber_set].to_ber_sequence
        end
        [entry[:dn].to_ber, attributes.to_ber_sequence].to_ber_appsequence(SEARCH_ENTRY)
      end

      # An LDAPResult (resultCode, matchedDN, diagnosticMessage) under a tag.
      def result(code, tag)
        [code.to_ber_enumerated, "".to_ber, "".to_ber].to_ber_appsequence(tag)
      end

      def write(connection, message_id, operation_ber)
        connection.write([message_id.to_ber, operation_ber].to_ber_sequence)
        nil
      end
    end
  end
end
