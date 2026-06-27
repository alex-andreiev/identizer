# frozen_string_literal: true

require "spec_helper"
require "identizer/ldap"
require "net/ldap"
require "tmpdir"

RSpec.describe Identizer::Ldap::Server do
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

  let(:port) { free_port }
  let(:config) do
    Identizer::Configuration.new.tap do |c|
      c.config_dir = @dir
      c.shared_password = "secret"
      c.seed_identities = [
        { mail: "alice@example.com", givenName: "Alice", sn: "Doe", memberOf: ["admins"] },
        { mail: "bob@example.com", givenName: "Bob", sn: "Jones" }
      ]
    end
  end

  # Boot the listener for the duration of a block.
  def with_server
    server = described_class.new(config, host: "127.0.0.1", port: port)
    thread = Thread.new { server.start }
    wait_until_listening
    yield
  ensure
    server.stop
    thread&.join(2)
  end

  def wait_until_listening
    20.times do
      TCPSocket.new("127.0.0.1", port).close
      return
    rescue StandardError
      sleep 0.05
    end
  end

  def client
    Net::LDAP.new(host: "127.0.0.1", port: port)
  end

  def alice_dn = "uid=alice,ou=people,dc=identizer,dc=local"

  describe "bind" do
    it "accepts a valid DN + shared password" do
      with_server do
        ldap = client
        ldap.auth(alice_dn, "secret")
        expect(ldap.bind).to be(true)
      end
    end

    it "rejects a wrong password" do
      with_server do
        ldap = client
        ldap.auth(alice_dn, "nope")
        expect(ldap.bind).to be(false)
      end
    end

    it "rejects an unknown DN" do
      with_server do
        ldap = client
        ldap.auth("uid=ghost,ou=people,dc=identizer,dc=local", "secret")
        expect(ldap.bind).to be(false)
      end
    end
  end

  describe "search" do
    def search(filter)
      entries = nil
      with_server do
        ldap = client
        ldap.auth(alice_dn, "secret")
        entries = ldap.search(base: "dc=identizer,dc=local", filter: filter,
                              scope: Net::LDAP::SearchScope_WholeSubtree)
      end
      Array(entries)
    end

    it "finds an entry by an equality filter and projects LDAP attributes" do
      results = search(Net::LDAP::Filter.eq("mail", "alice@example.com"))
      expect(results.size).to eq(1)
      entry = results.first
      expect(entry.dn).to eq(alice_dn)
      expect(entry[:mail]).to eq(["alice@example.com"])
      expect(entry[:givenname]).to eq(["Alice"])
      expect(entry[:objectclass]).to include("inetOrgPerson")
      expect(entry[:memberof]).to eq(["admins"])
    end

    it "returns all entries for a presence filter" do
      results = search(Net::LDAP::Filter.present("objectclass"))
      expect(results.map(&:dn)).to contain_exactly(
        alice_dn, "uid=bob,ou=people,dc=identizer,dc=local"
      )
    end

    it "supports compound AND filters" do
      filter = Net::LDAP::Filter.eq("uid", "alice") & Net::LDAP::Filter.present("mail")
      expect(search(filter).map(&:dn)).to eq([alice_dn])
    end

    it "supports negation" do
      filter = Net::LDAP::Filter.present("objectclass") & ~Net::LDAP::Filter.eq("uid", "bob")
      expect(search(filter).map(&:dn)).to eq([alice_dn])
    end

    it "supports substring filters" do
      expect(search(Net::LDAP::Filter.eq("mail", "ali*")).map(&:dn)).to eq([alice_dn])
    end

    it "returns nothing when the base DN does not match" do
      results = nil
      with_server do
        ldap = client
        ldap.auth(alice_dn, "secret")
        results = ldap.search(base: "dc=other,dc=org", filter: Net::LDAP::Filter.present("objectclass"),
                              scope: Net::LDAP::SearchScope_WholeSubtree)
      end
      expect(Array(results)).to be_empty
    end
  end
end
