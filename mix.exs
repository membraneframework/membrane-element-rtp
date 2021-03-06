defmodule Membrane.Element.RTP.MixProject do
  use Mix.Project

  @version "0.3.0"
  @github_url "https://github.com/membraneframework/membrane-element-rtp"

  def project do
    [
      app: :membrane_element_rtp,
      version: @version,
      elixir: "~> 1.7",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      description: "Membrane Multimedia Framework (RTP Element)",
      package: package(),
      name: "Membrane Element: RTP",
      source_url: @github_url,
      docs: docs(),
      homepage_url: "https://membraneframework.org",
      test_coverage: [tool: ExCoveralls],
      deps: deps(),
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ]
    ]
  end

  def application do
    [
      extra_applications: []
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      source_ref: "v#{@version}"
    ]
  end

  defp package do
    [
      maintainers: ["Membrane Team"],
      licenses: ["Apache 2.0"],
      links: %{
        "GitHub" => @github_url,
        "Membrane Framework Homepage" => "https://membraneframework.org"
      }
    ]
  end

  defp deps do
    [
      {:membrane_core, "~> 0.5.0"},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:membrane_caps_rtp, "~> 0.1"},
      {:excoveralls, "~> 0.8", only: :test}
    ]
  end
end
