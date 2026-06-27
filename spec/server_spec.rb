# frozen_string_literal: true

require "spec_helper"
require "tmpdir"
require "socket"
require "net/http"

# Boots the real WEBrick server on an ephemeral port and exercises the full
# WEBrick -> Rack env translation over HTTPS.
RSpec.describe Identizer::Server do
  around do |example|
    Dir.mktmpdir do |dir|
      @dir = dir
      example.run
    end
  end

  def free_port
    socket = TCPServer.new("127.0.0.1", 0)
    port = socket.addr[1]
    socket.close
    port
  end

  def get_with_retry(http, path)
    20.times do
      return http.get(path)
    rescue StandardError
      sleep 0.1
    end
    nil
  end

  it "serves the app over HTTPS end to end" do
    port = free_port
    config = Identizer::Configuration.new.tap do |c|
      c.config_dir = @dir
      c.port = port
      c.seed_identities = [{ mail: "alice@example.com" }]
    end

    server = described_class.new(config).mounted_server
    thread = Thread.new { server.start }

    http = Net::HTTP.new("127.0.0.1", port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.open_timeout = 5
    http.read_timeout = 5

    overview = get_with_retry(http, "/")
    directory = http.get("/directory")

    expect(overview.code).to eq("200")
    expect(overview.body).to include("Identizer")
    expect(directory.body).to include("alice@example.com")
  ensure
    server&.shutdown
    thread&.join(2)
  end
end
