# Usage: mix run --no-start decode_capture.exs <file.bin> [--no-hex] [--filter NAME]
#
# Reads a .bin capture file and prints decoded packets with field values.

# Boot only the modules we need (no listener/proxy)
Application.ensure_all_started(:jason)
Application.ensure_all_started(:nimble_lz4)
Vampir.Opcodes.start_link([])
Vampir.Decoder.start_link([])

alias Vampir.{Packet, Decoder}

{opts, args, _} =
  OptionParser.parse(System.argv(), strict: [no_hex: :boolean, filter: :string])

file =
  case args do
    [path] -> path
    _ ->
      IO.puts("Usage: mix run decode_capture.exs <file.bin> [--no-hex] [--filter NAME]")
      System.halt(1)
  end

no_hex = Keyword.get(opts, :no_hex, false)
filter = Keyword.get(opts, :filter)

# Parse .bin format: repeated [u32 meta_len][meta][u64 ts][u32 body_len][body]
defmodule BinReader do
  def read_entries(data), do: read_entries(data, [])

  defp read_entries(<<meta_len::32, meta::binary-size(meta_len),
                      _ts::64,
                      body_len::32, body::binary-size(body_len),
                      rest::binary>>, acc) do
    read_entries(rest, [{meta, body} | acc])
  end

  defp read_entries(_, acc), do: Enum.reverse(acc)
end

data = File.read!(file)
entries = BinReader.read_entries(data)

# Collect raw chunks per direction in order, then feed through Packet reassembler
{c2s_chunks, s2c_chunks} =
  Enum.reduce(entries, {[], []}, fn {meta, body}, {c2s, s2c} ->
    cond do
      String.starts_with?(meta, "C->S raw") -> {[body | c2s], s2c}
      String.starts_with?(meta, "S->C raw") -> {c2s, [body | s2c]}
      true -> {c2s, s2c}
    end
  end)

decode_stream = fn chunks, dir ->
  chunks
  |> Enum.reverse()
  |> Enum.reduce({[], Packet.new(dir)}, fn chunk, {pkts, state} ->
    {new_pkts, new_state} = Packet.feed(state, chunk)
    {pkts ++ new_pkts, new_state}
  end)
  |> elem(0)
end

c2s_pkts = decode_stream.(c2s_chunks, "C->S")
s2c_pkts = decode_stream.(s2c_chunks, "S->C")

# Interleave by seq (they're independent counters, so group by direction)
all =
  Enum.map(c2s_pkts, &Map.put(&1, :sort_key, {0, &1.seq})) ++
  Enum.map(s2c_pkts, &Map.put(&1, :sort_key, {1, &1.seq}))
  |> Enum.sort_by(& &1.sort_key)

for pkt <- all do
  skip =
    cond do
      filter && pkt.name && not String.contains?(pkt.name, filter) -> true
      filter && pkt.name == nil -> true
      true -> false
    end

  unless skip do
    dir = pkt.direction
    op_str = if pkt.opcode, do: "op=#{pkt.opcode}", else: "op=?"
    name_str = pkt.name || "Unknown"
    lz4_str = if pkt[:compressed], do: " LZ4→#{pkt[:decompressed_size] || "?"}B", else: ""
    err_str = if pkt[:error], do: " [#{pkt[:error]}]", else: ""

    IO.puts("[#{dir}] ##{pkt.seq} [#{pkt.raw_size}B#{lz4_str}] #{op_str} #{name_str}#{err_str}")

    unless no_hex do
      IO.puts(Packet.hexdump(pkt.data, 256))
    end

    if pkt.opcode do
      case Decoder.decode_fields(pkt.opcode, pkt.data) do
        {:ok, []} -> :ok
        {:ok, fields} -> IO.puts(Decoder.format_fields(fields))
        {:error, _} -> :ok
      end
    end

    IO.puts("")
  end
end
