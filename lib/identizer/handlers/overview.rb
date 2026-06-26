# frozen_string_literal: true

module Identizer
  module Handlers
    # The web-admin home: status, the provider cheatsheet, and links into the rest.
    class Overview < Base
      def index(request)
        page("overview/index", request, nav: :overview, title: "Overview",
                                        config: config, count: directory_size)
      end

      private

      def directory_size
        store.respond_to?(:entries) ? store.entries.size : store.emails.size
      end
    end
  end
end
