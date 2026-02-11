defmodule Vampir.Opcodes do
  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def lookup(opcode) do
    case :ets.lookup(__MODULE__, opcode) do
      [{^opcode, name}] -> name
      [] -> nil
    end
  end

  @impl true
  def init(_) do
    :ets.new(__MODULE__, [:named_table, :set, :public, read_concurrency: true])

    json_path =
      [File.cwd!(), "..", "packet_opcodes.json"]
      |> Path.join()
      |> Path.expand()

    case File.read(json_path) do
      {:ok, data} ->
        %{"opcode_map" => map} = Jason.decode!(data)

        for {k, v} <- map do
          :ets.insert(__MODULE__, {String.to_integer(k), v})
        end

        IO.puts("[opcodes] Loaded #{map_size(map)} opcodes from #{json_path}")

      {:error, reason} ->
        IO.puts("[opcodes] WARNING: Could not load #{json_path}: #{reason}")
    end

    {:ok, %{}}
  end
end
