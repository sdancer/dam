defmodule Vampir.Inject do
  @moduledoc "Inject crafted packets to the game server via the proxied connection."
  use GenServer

  alias Vampir.Crypto

  @table :vampir_inject

  def start_link(_opts), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @doc "Register the server-side socket for packet injection."
  def register_socket(socket), do: :ets.insert(@table, {:server_socket, socket})

  @doc "Unregister the server-side socket."
  def unregister_socket, do: :ets.delete(@table, :server_socket)

  @doc "Send a crafted C->S packet to the game server."
  def send_packet(opcode, payload \\ <<>>) do
    case :ets.lookup(@table, :server_socket) do
      [{:server_socket, socket}] ->
        plaintext = <<0x9A, :erlang.crc32(<<opcode::little-16, payload::binary>>)::little-32, opcode::little-16, payload::binary>>
        body = Crypto.xor_decrypt(plaintext, 0)
        total_len = byte_size(body) + 2
        wire = <<total_len::little-16, body::binary>>
        :gen_tcp.send(socket, wire)

      [] ->
        {:error, :no_socket}
    end
  end

  @impl true
  def init(_) do
    :ets.new(@table, [:named_table, :public, :set])
    {:ok, %{}}
  end
end
