defmodule Vampir.Capture do
  @moduledoc "Stores raw packet captures per stream in ETS, flushes to disk every 10s."
  use GenServer

  @flush_interval 10_000
  @table :vampir_capture
  @dump_dir "captures"

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc "Register a new connection, returns a stream_id used for store calls."
  def new_stream(ip, port) do
    ts = timestamp_str()
    stream_id = "#{ts}_#{ip}_#{port}"
    File.mkdir_p!(@dump_dir)
    stream_id
  end

  @doc "Store a raw TCP chunk."
  def store(stream_id, direction, seq, raw_data) do
    ts = System.system_time(:microsecond)
    key = {stream_id, direction}
    :ets.insert(@table, {{key, ts, seq}, {:raw, raw_data}})
  end

  @doc "Store a decoded packet."
  def store_packet(stream_id, direction, %{seq: seq, opcode: op, name: name, raw_size: size}, raw_body) do
    ts = System.system_time(:microsecond)
    key = {stream_id, direction}
    :ets.insert(@table, {{key, ts, seq}, {:pkt, op, name, size, raw_body}})
  end

  @impl true
  def init(_) do
    :ets.new(@table, [:named_table, :ordered_set, :public, write_concurrency: true])
    File.mkdir_p!(@dump_dir)
    schedule_flush()
    IO.puts("[capture] Storing to ETS, flushing to #{@dump_dir}/ every #{div(@flush_interval, 1000)}s")
    {:ok, %{}}
  end

  @impl true
  def handle_info(:flush, state) do
    flush_to_disk()
    schedule_flush()
    {:noreply, state}
  end

  defp schedule_flush do
    Process.send_after(self(), :flush, @flush_interval)
  end

  defp timestamp_str do
    {{y, m, d}, {h, min, s}} = :calendar.local_time()
    "#{y}#{pad(m)}#{pad(d)}_#{pad(h)}#{pad(min)}#{pad(s)}"
  end

  defp pad(n), do: String.pad_leading(Integer.to_string(n), 2, "0")

  defp flush_to_disk do
    entries = :ets.tab2list(@table)
    if entries == [], do: :ok, else: do_flush(entries)
  end

  defp do_flush(entries) do
    # Group by stream_id (both directions in same file)
    grouped =
      Enum.group_by(entries, fn {{{stream_id, _dir}, _ts, _seq}, _payload} -> stream_id end)

    total = length(entries)

    for {stream_id, stream_entries} <- grouped do
      path = Path.join(@dump_dir, "#{stream_id}.bin")

      data =
        stream_entries
        |> Enum.sort_by(fn {{_key, ts, seq}, _} -> {ts, seq} end)
        |> Enum.map(&encode_entry/1)

      File.write!(path, data, [:append])
    end

    :ets.delete_all_objects(@table)
    streams = map_size(grouped)
    IO.puts("[capture] Flushed #{total} entries across #{streams} streams")
  end

  defp encode_entry({{{_stream, dir}, ts, seq}, {:raw, raw_data}}) do
    meta = "#{dir} raw ##{seq}"
    <<byte_size(meta)::32, meta::binary, ts::64, byte_size(raw_data)::32, raw_data::binary>>
  end

  defp encode_entry({{{_stream, dir}, ts, seq}, {:pkt, op, name, _size, raw_body}}) do
    meta = "#{dir} pkt ##{seq} op=#{op || "?"} #{name || "?"}"
    <<byte_size(meta)::32, meta::binary, ts::64, byte_size(raw_body)::32, raw_body::binary>>
  end
end
