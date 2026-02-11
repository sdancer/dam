defmodule Vampir.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Vampir.Opcodes, []},
      {Vampir.Decoder, []},
      {Vampir.Inject, []},
      {Vampir.Capture, []},
      {Vampir.Proxy.Listener, port: 9021}
    ]

    opts = [strategy: :one_for_one, name: Vampir.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
