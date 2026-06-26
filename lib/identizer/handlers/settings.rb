# frozen_string_literal: true

module Identizer
  module Handlers
    # View and edit runtime settings (shared password, token signing), persisted
    # to settings.json so the standalone server picks them up on the next boot.
    class Settings < Base
      def show(request)
        page("settings/index", request, nav: :settings, title: "Settings", config: config)
      end

      def update(request)
        password = request.params["shared_password"].to_s
        config.shared_password = password unless password.empty?
        config.signing = request.params["signing"] == "rs256" ? :rs256 : :hs256
        config.persist_settings!

        redirect("#{request.script_name}/settings")
      end
    end
  end
end
