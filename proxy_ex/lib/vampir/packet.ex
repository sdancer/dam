defmodule Vampir.Packet do
  @moduledoc "Reassemble length-prefixed packets from a TCP stream and decode opcodes."

  alias Vampir.Crypto
  alias Vampir.Opcodes

  defstruct buffer: <<>>, count: 0, direction: "?"

  def new(direction \\ "?"), do: %__MODULE__{direction: direction}

  @doc "Feed raw TCP data into the reassembler. Returns {decoded_packets, new_state}."
  def feed(%__MODULE__{buffer: buf, count: count, direction: dir} = _state, data) do
    buf = buf <> data
    {packets, remaining, new_count} = extract_loop(buf, count, dir, [])
    {packets, %__MODULE__{buffer: remaining, count: new_count, direction: dir}}
  end

  # Main extraction loop: read u16 LE length, cut that many bytes, decode, repeat
  defp extract_loop(buf, count, dir, acc) do
    case buf do
      # Need at least 2 bytes to read the length prefix
      <<pkt_len::little-16, _rest::binary>> when pkt_len >= 4 and byte_size(buf) >= pkt_len ->
        # Cut exactly pkt_len bytes (includes the 2-byte length itself)
        body_len = pkt_len - 2
        <<_len::little-16, body::binary-size(body_len), remaining::binary>> = buf
        seq = count + length(acc) + 1
        decoded = decode(body, seq, dir)
        extract_loop(remaining, count, dir, [decoded | acc])

      <<pkt_len::little-16, _rest::binary>> when pkt_len < 4 ->
        # Bogus length, skip 1 byte and retry
        <<_, remaining::binary>> = buf
        extract_loop(remaining, count, dir, acc)

      _ ->
        # Not enough data yet, keep buffer
        new_count = count + length(acc)
        {Enum.reverse(acc), buf, new_count}
    end
  end

  defp decode(body, seq, dir) do
    case {dir, body} do
      # S->C compressed: flag 0x80 + LZ4 compressed XOR-encrypted data
      {d, <<0x80, lz4_data::binary>>} when d != "C->S" ->
        decode_compressed(lz4_data, body, seq, dir)

      # Normal: XOR decrypt whole body
      _ ->
        {key_offset, opcode_offset} =
          case dir do
            "C->S" -> {0, 5}
            _s2c -> {5, 4}
          end

        decrypted = Crypto.xor_decrypt(body, key_offset)
        opcode = extract_opcode(decrypted, opcode_offset)
        name = if opcode, do: Opcodes.lookup(opcode)
        payload_offset = opcode_offset + 2
        payload = if byte_size(decrypted) > payload_offset, do: binary_part(decrypted, payload_offset, byte_size(decrypted) - payload_offset), else: <<>>

        %{
          seq: seq,
          raw_size: byte_size(body) + 2,
          opcode: opcode,
          name: name,
          data: payload,
          raw: body,
          direction: dir
        }
    end
  end

  # LZ4 decompress, then XOR decrypt with offset 6, opcode at byte 3
  defp decode_compressed(lz4_data, raw_body, seq, dir) do
    case Crypto.lz4_decompress(lz4_data) do
      {:ok, decompressed} ->
        decrypted = Crypto.xor_decrypt(decompressed, 6)
        opcode = extract_opcode(decrypted, 3)
        name = if opcode, do: Opcodes.lookup(opcode)
        payload = if byte_size(decrypted) > 5, do: binary_part(decrypted, 5, byte_size(decrypted) - 5), else: <<>>

        %{
          seq: seq,
          raw_size: byte_size(raw_body) + 2,
          opcode: opcode,
          name: name,
          data: payload,
          raw: raw_body,
          direction: dir,
          compressed: true,
          decompressed_size: byte_size(decompressed)
        }

      {:error, reason} ->
        %{
          seq: seq,
          raw_size: byte_size(raw_body) + 2,
          opcode: nil,
          name: nil,
          data: raw_body,
          raw: raw_body,
          direction: dir,
          compressed: true,
          error: "LZ4: #{reason}"
        }
    end
  end

  defp extract_opcode(data, offset) when byte_size(data) >= offset + 2 do
    <<_head::binary-size(offset), opcode::little-16, _rest::binary>> = data
    opcode
  end

  defp extract_opcode(_, _), do: nil

  def format_packet(%{seq: seq, opcode: op, name: name, raw_size: size, data: dec} = pkt) do
    op_str = if op, do: "op=#{op}", else: "op=?"
    name_str = name || "Unknown"
    lz4_str = if pkt[:compressed], do: " LZ4→#{pkt[:decompressed_size] || "?"}B", else: ""
    err_str = if pkt[:error], do: " [#{pkt[:error]}]", else: ""
    header = "##{seq} [#{size}B#{lz4_str}] #{op_str} #{name_str}#{err_str}"
    hex = hexdump(dec, 256)

    fields_str =
      if op do
        case Vampir.Decoder.decode_fields(op, dec) do
          {:ok, []} -> ""
          {:ok, fields} -> "\n" <> Vampir.Decoder.format_fields(fields)
          {:error, _} -> ""
        end
      else
        ""
      end

    "#{header}\n#{hex}#{fields_str}"
  end

  def hexdump(data, limit \\ nil) do
    data = if limit && byte_size(data) > limit, do: binary_part(data, 0, limit), else: data
    bytes = :binary.bin_to_list(data)

    bytes
    |> Enum.chunk_every(16)
    |> Enum.with_index()
    |> Enum.map(fn {chunk, row} ->
      offset = row * 16
      hex = chunk |> Enum.map(&String.pad_leading(Integer.to_string(&1, 16), 2, "0")) |> Enum.join(" ")
      ascii = chunk |> Enum.map(fn b -> if b >= 32 and b < 127, do: <<b>>, else: "." end) |> Enum.join()
      "    #{String.pad_leading(Integer.to_string(offset, 16), 4, "0")}  #{String.pad_trailing(hex, 48)}  #{ascii}"
    end)
    |> Enum.join("\n")
  end
end
