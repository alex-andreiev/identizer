# frozen_string_literal: true

# Example rackup config. NOTE: Identizer's login flow needs https; prefer the
# `identizer` CLI (which terminates TLS) for the full popup flow. This is handy
# for mounting/inspecting the app behind your own TLS-terminating server.
require "identizer"

run Identizer.app
