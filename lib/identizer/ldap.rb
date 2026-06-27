# frozen_string_literal: true

# Optional LDAP listener. Required on demand (e.g. by the CLI when --ldap-port is
# set) so the net-ldap dependency is only loaded when the feature is used.
require "net/ldap"
require "socket"

module Identizer
  # A minimal LDAP v3 server backed by the identity directory.
  module Ldap
  end
end

require_relative "ldap/filter"
require_relative "ldap/handler"
require_relative "ldap/server"
