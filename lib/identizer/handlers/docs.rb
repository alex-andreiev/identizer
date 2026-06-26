# frozen_string_literal: true

module Identizer
  module Handlers
    # Bundled, read-only documentation pages under /docs.
    class Docs < Base
      def index(request)
        page("docs/index", request, nav: :docs, title: "Docs", pages: Identizer::Docs::PAGES)
      end

      def show(request, slug)
        meta = Identizer::Docs.find(slug)
        return not_found("No doc page: #{slug}") unless meta

        page("docs/#{slug}", request, nav: :docs, title: meta[:title], config: config)
      end
    end
  end
end
