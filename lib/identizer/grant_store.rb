# frozen_string_literal: true

module Identizer
  # A small thread-safe, TTL'd key -> value store for the short-lived grants the
  # provider issues (authorization codes, access tokens, refresh tokens). Entries
  # expire and are pruned lazily on access, so the maps don't grow without bound
  # and the advertised lifetimes are actually enforced. Uses a monotonic clock so
  # it's immune to wall-clock changes.
  class GrantStore
    def initialize
      @entries = {}
      @mutex = Mutex.new
    end

    def put(key, value, ttl:)
      @mutex.synchronize { @entries[key] = [value, monotonic + ttl] }
      value
    end

    # Read without consuming; nil if missing or expired.
    def get(key)
      @mutex.synchronize { fetch(key) }
    end

    # Read and remove (single-use); nil if missing or expired.
    def take(key)
      @mutex.synchronize do
        value = fetch(key)
        @entries.delete(key)
        value
      end
    end

    def size
      @mutex.synchronize { @entries.size }
    end

    private

    def fetch(key)
      entry = @entries[key]
      return nil unless entry

      value, expires_at = entry
      return value if monotonic < expires_at

      @entries.delete(key)
      nil
    end

    def monotonic
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
