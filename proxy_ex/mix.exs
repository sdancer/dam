defmodule Vampir.MixProject do
  use Mix.Project

  def project do
    [
      app: :vampir,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {Vampir.Application, []}
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:nimble_lz4, "~> 1.1"}
    ]
  end
end
