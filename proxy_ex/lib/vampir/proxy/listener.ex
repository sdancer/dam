defmodule Vampir.Proxy.Listener do
  use GenServer
  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    port = Keyword.fetch!(opts, :port)

    {:ok, listen_sock} =
      :gen_tcp.listen(port, [
        :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        backlog: 128
      ])

    IO.puts("[proxy] Listening on 0.0.0.0:#{port}")
    spawn_link(fn -> accept_loop(listen_sock) end)
    {:ok, %{listen_sock: listen_sock, port: port}}
  end

  defp accept_loop(listen_sock) do
    case :gen_tcp.accept(listen_sock) do
      {:ok, client} ->
        spawn(fn -> Vampir.Proxy.Handler.handle(client) end)
        accept_loop(listen_sock)

      {:error, reason} ->
        IO.puts("[proxy] Accept error: #{reason}")
        accept_loop(listen_sock)
    end
  end
end
