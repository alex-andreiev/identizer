# frozen_string_literal: true

require "erb"

module Identizer
  # Minimal ERB renderer with a shared layout. Templates live under web/views and
  # are rendered in a Context that exposes the passed locals plus an `h` escaping
  # helper. No template-engine dependency — stdlib ERB only.
  class Renderer
    VIEWS_DIR = File.expand_path("web/views", __dir__)

    def initialize(layout: "layout")
      @layout = layout
      @cache = {}
    end

    def render(template, **locals)
      content = render_template(template, locals)
      render_template(@layout, locals.merge(content: content))
    end

    # Render a standalone template without the admin layout (e.g. the login form).
    def render_bare(template, **locals)
      render_template(template, locals)
    end

    private

    def render_template(name, locals)
      template(name).result(Context.new(locals).binding_for)
    end

    def template(name)
      @cache[name] ||= ERB.new(File.read(File.join(VIEWS_DIR, "#{name}.html.erb")), trim_mode: "-")
    end

    # Evaluation context: locals become reader methods; `h` escapes HTML.
    class Context
      def initialize(locals)
        locals.each { |key, value| define_singleton_method(key) { value } }
      end

      def h(value)
        CGI.escapeHTML(value.to_s)
      end

      def binding_for
        binding
      end
    end
  end
end
