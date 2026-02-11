defmodule Vampir.Decoder do
  @moduledoc "Decode packet payload fields using packet_field_types_v2.json definitions."
  use GenServer

  @table :vampir_decoder

  # Packets whose base class serializes a uint32 before defined fields.
  # Detected empirically from captures. Add opcodes here as discovered.
  @base_prefix_opcodes MapSet.new([
    608,   # PktSkillStartResult
    1811,  # PktQuestUpdateResult
    2046   # PktChatReportAndBanInfoReadResult
  ])

  # Full field list overrides (keyed by opcode). Use sparingly.
  @field_overrides %{}

  def start_link(_opts), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @doc "Decode payload fields for a given opcode. Returns {:ok, fields} or {:error, reason}."
  def decode_fields(opcode, payload) when is_integer(opcode) and is_binary(payload) do
    case :ets.lookup(@table, opcode) do
      [{^opcode, fields_def}] ->
        decode_sequential(fields_def, payload, [])

      [] ->
        {:error, :no_definition}
    end
  end

  defp decode_sequential([], _rest, acc), do: {:ok, Enum.reverse(acc)}
  defp decode_sequential(_fields, <<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_sequential([%{"name" => name, "type" => type} | rest], data, acc) do
    effective_type = maybe_override_type(name, type)

    case decode_field(effective_type, data) do
      {:ok, value, remaining} ->
        decode_sequential(rest, remaining, [{name, value} | acc])

      :stop ->
        {:ok, Enum.reverse([{name, {:remaining, data}} | acc])}
    end
  end

  # Position/rotation fields typed as int32 are actually floats
  @float_names ~w(PosX PosY PosZ TargetPosX TargetPosY TargetPosZ Dir Yaw Pitch Roll)
  defp maybe_override_type(name, "int32") when name in @float_names, do: "float"
  defp maybe_override_type(_name, type), do: type

  defp decode_field("int8", <<v::signed-8, rest::binary>>), do: {:ok, v, rest}
  defp decode_field("uint8", <<v::unsigned-8, rest::binary>>), do: {:ok, v, rest}
  defp decode_field("int16", <<v::little-signed-16, rest::binary>>), do: {:ok, v, rest}
  defp decode_field("uint16", <<v::little-unsigned-16, rest::binary>>), do: {:ok, v, rest}
  defp decode_field("int32", <<v::little-signed-32, rest::binary>>), do: {:ok, v, rest}
  defp decode_field("uint32", <<v::little-unsigned-32, rest::binary>>), do: {:ok, v, rest}
  defp decode_field("int64", <<v::little-signed-64, rest::binary>>), do: {:ok, v, rest}
  defp decode_field("uint64", <<v::little-unsigned-64, rest::binary>>), do: {:ok, v, rest}
  defp decode_field("bool", <<v::little-unsigned-32, rest::binary>>), do: {:ok, v != 0, rest}
  defp decode_field("float", <<v::little-float-32, rest::binary>>), do: {:ok, v, rest}

  defp decode_field("FVector", <<x::little-float-32, y::little-float-32, z::little-float-32, rest::binary>>) do
    {:ok, {x, y, z}, rest}
  end

  defp decode_field("FVector2D", <<x::little-float-32, y::little-float-32, rest::binary>>) do
    {:ok, {x, y}, rest}
  end

  defp decode_field(type, data) when type in ["string", "FName"] do
    decode_ue_string(data)
  end

  # struct, TArray, TMap, TSet, bytes, unknown, and anything else -> stop
  defp decode_field(_type, _data), do: :stop

  # UE FArchive string: i32 length (negative = UTF-16), includes null terminator
  defp decode_ue_string(<<len::little-signed-32, rest::binary>>) when len >= 0 do
    if byte_size(rest) >= len do
      <<raw::binary-size(len), remaining::binary>> = rest
      # Strip null terminator if present
      str = if len > 0 and :binary.last(raw) == 0, do: binary_part(raw, 0, len - 1), else: raw
      {:ok, str, remaining}
    else
      :stop
    end
  end

  defp decode_ue_string(<<len::little-signed-32, rest::binary>>) when len < 0 do
    # UTF-16: length is negative, char count = -len, byte count = -len * 2
    char_count = -len
    byte_count = char_count * 2

    if byte_size(rest) >= byte_count do
      <<raw::binary-size(byte_count), remaining::binary>> = rest
      # Strip null terminator (2 bytes) and decode UTF-16LE
      str_bytes = if char_count > 0, do: binary_part(raw, 0, byte_count - 2), else: raw

      case :unicode.characters_to_binary(str_bytes, {:utf16, :little}) do
        s when is_binary(s) -> {:ok, s, remaining}
        _ -> {:ok, str_bytes, remaining}
      end
    else
      :stop
    end
  end

  defp decode_ue_string(_), do: :stop

  @doc "Format decoded fields as a string for display."
  def format_fields(fields) do
    fields
    |> Enum.map(fn
      {name, {:remaining, data}} ->
        "    #{name}: <remaining #{byte_size(data)}B>"

      {name, {x, y, z}} when is_float(x) and is_float(y) and is_float(z) ->
        "    #{name}: (#{Float.round(x, 2)}, #{Float.round(y, 2)}, #{Float.round(z, 2)})"

      {name, {x, y}} when is_float(x) and is_float(y) ->
        "    #{name}: (#{Float.round(x, 2)}, #{Float.round(y, 2)})"

      {name, value} when is_binary(value) ->
        display = if String.printable?(value), do: inspect(value), else: "#{byte_size(value)}B"
        "    #{name}: #{display}"

      {name, value} when is_boolean(value) ->
        "    #{name}: #{value}"

      {name, value} when is_float(value) ->
        "    #{name}: #{Float.round(value, 4)}"

      {name, value} ->
        "    #{name}: #{value}"
    end)
    |> Enum.join("\n")
  end

  @impl true
  def init(_) do
    :ets.new(@table, [:named_table, :protected, :set])
    load_definitions()
    {:ok, %{}}
  end

  defp load_definitions do
    path = Path.join([Application.app_dir(:vampir), "..", "..", "..", "packet_field_types_v2.json"])
    |> Path.expand()

    # Fallback: try relative from project root
    path = if File.exists?(path), do: path, else: Path.expand("../packet_field_types_v2.json")

    case File.read(path) do
      {:ok, json} ->
        data = Jason.decode!(json)
        packets = Map.get(data, "packets", %{})

        count =
          Enum.reduce(packets, 0, fn {_name, info}, n ->
            opcode = Map.get(info, "opcode")
            fields = Map.get(info, "fields", [])

            if opcode && fields != [] do
              :ets.insert(@table, {opcode, fields})
              n + 1
            else
              n
            end
          end)

        IO.puts("[decoder] Loaded #{count} packet definitions")
        apply_overrides()

      {:error, reason} ->
        IO.puts("[decoder] Failed to load definitions: #{inspect(reason)} (tried #{path})")
    end
  end

  @base_field %{"name" => "_base", "type" => "uint32"}

  defp apply_overrides do
    # Prepend base class uint32 to packets that serialize it
    base_count =
      Enum.count(@base_prefix_opcodes, fn opcode ->
        case :ets.lookup(@table, opcode) do
          [{^opcode, fields}] ->
            :ets.insert(@table, {opcode, [@base_field | fields]})
            true
          _ -> false
        end
      end)

    # Apply full field overrides
    for {opcode, fields} <- @field_overrides do
      :ets.insert(@table, {opcode, fields})
    end

    total = base_count + map_size(@field_overrides)
    if total > 0, do: IO.puts("[decoder] Applied #{total} field corrections (#{base_count} base prefix)")
  end
end
