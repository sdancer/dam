defmodule Vampir.Crypto do
  @xor_key <<0x9A, 0xA7, 0x84, 0x20, 0xD0, 0xC9, 0x78, 0xB3>>
  @key_len byte_size(@xor_key)

  def xor_decrypt(data, key_offset \\ 0) when is_binary(data) do
    for {byte, i} <- Enum.with_index(:binary.bin_to_list(data)),
        into: <<>> do
      <<Bitwise.bxor(byte, :binary.at(@xor_key, rem(i + key_offset, @key_len)))>>
    end
  end

  @doc "LZ4 block decompress. Discovers actual size via NimbleLZ4 error message."
  def lz4_decompress(data) when is_binary(data) do
    # First attempt with generous buffer
    big = max(byte_size(data) * 20, 262_144)

    case NimbleLZ4.decompress(data, big) do
      {:ok, result} ->
        {:ok, result}

      {:error, msg} ->
        # NimbleLZ4 reports actual size: "actual N, expected M"
        case Regex.run(~r/actual (\d+)/, msg) do
          [_, size_str] ->
            NimbleLZ4.decompress(data, String.to_integer(size_str))

          _ ->
            {:error, msg}
        end
    end
  end
end
