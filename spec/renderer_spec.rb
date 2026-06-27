# frozen_string_literal: true

require "spec_helper"

RSpec.describe Identizer::Renderer do
  subject(:renderer) { described_class.new }

  it "renders a template inside the layout with the given locals" do
    out = renderer.render("docs/index", nav: :docs, title: "Docs", prefix: "/idp",
                                        pages: [{ slug: "x", title: "Page X" }])
    expect(out).to include("<title>Docs · Identizer</title>")
    expect(out).to include('href="/idp/docs/x"', "Page X")
  end

  it "escapes interpolated values through the h helper" do
    out = renderer.render("docs/index", nav: :docs, title: "Docs", prefix: "",
                                        pages: [{ slug: "x", title: "<script>" }])
    expect(out).to include("&lt;script&gt;")
    expect(out).not_to include("<script>x")
  end
end
