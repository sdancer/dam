defmodule Vampir.Proxy.Handler do
  # Configure these for your environment
  @upstream_host ~c"127.0.0.1"
  @upstream_port 12323
  @upstream_auth Base.encode64("user:pass")

  @passthrough_hosts MapSet.new([])
  @game_ports MapSet.new([12000])

  # Linux SO_ORIGINAL_DST
  @sol_ip 0
  @so_original_dst 80

  def handle(client) do
    case get_original_dst(client) do
      {:ok, ip, port} ->
        cond do
          MapSet.member?(@passthrough_hosts, {ip, port}) ->
            handle_passthrough(client, ip, port)

          MapSet.member?(@game_ports, port) ->
            handle_game(client, ip, port)

          true ->
            handle_upstream(client, ip, port)
        end

      {:error, reason} ->
        IO.puts("[proxy] Failed to get original dst: #{reason}")
        :gen_tcp.close(client)
    end
  end

  defp get_original_dst(sock) do
    case :inet.getopts(sock, [{:raw, @sol_ip, @so_original_dst, 16}]) do
      {:ok, [{:raw, @sol_ip, @so_original_dst, data}]} ->
        <<_family::little-16, port::big-16, a, b, c, d, _rest::binary>> = data
        {:ok, "#{a}.#{b}.#{c}.#{d}", port}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # --- Passthrough: direct connect, log headers once ---

  defp handle_passthrough(client, ip, port) do
    case :gen_tcp.connect(~c"#{ip}", port, [:binary, packet: :raw, active: false]) do
      {:ok, remote} ->
        case :gen_tcp.recv(client, 0, 5000) do
          {:ok, data} ->
            # Log headers first time
            header_end = :binary.match(data, "\r\n\r\n")

            headers =
              case header_end do
                {pos, _} -> binary_part(data, 0, pos)
                :nomatch -> binary_part(data, 0, min(512, byte_size(data)))
              end

            IO.puts("[passthrough] #{ip}:#{port}\n#{headers}\n")
            :gen_tcp.send(remote, data)
            relay(client, remote)

          {:error, _} ->
            :gen_tcp.close(client)
            :gen_tcp.close(remote)
        end

      {:error, reason} ->
        IO.puts("[passthrough] Connect failed #{ip}:#{port}: #{reason}")
        :gen_tcp.close(client)
    end
  end

  # --- Game port: direct connect, decrypt + decode packets ---

  defp handle_game(client, ip, port) do
    IO.puts("[game] #{ip}:#{port}")
    stream_id = Vampir.Capture.new_stream(ip, port)

    case :gen_tcp.connect(~c"#{ip}", port, [:binary, packet: :raw, active: false]) do
      {:ok, remote} ->
        Vampir.Inject.register_socket(remote)

        c2s_pid = spawn_link(fn -> game_relay(client, remote, "C->S", stream_id) end)
        s2c_pid = spawn_link(fn -> game_relay(remote, client, "S->C", stream_id) end)

        ref1 = Process.monitor(c2s_pid)
        ref2 = Process.monitor(s2c_pid)

        receive do
          {:DOWN, ^ref1, :process, _, _} -> :ok
          {:DOWN, ^ref2, :process, _, _} -> :ok
        end

        Vampir.Inject.unregister_socket()
        :gen_tcp.close(client)
        :gen_tcp.close(remote)

      {:error, reason} ->
        IO.puts("[game] Connect failed #{ip}:#{port}: #{reason}")
        :gen_tcp.close(client)
    end
  end

  defp game_relay(src, dst, label, stream_id) do
    game_relay_loop(src, dst, label, stream_id, Vampir.Packet.new(label), 0)
  end

  defp game_relay_loop(src, dst, label, stream_id, pkt_state, chunk_seq) do
    case :gen_tcp.recv(src, 0) do
      {:ok, data} ->
        :gen_tcp.send(dst, data)

        Vampir.Capture.store(stream_id, label, chunk_seq + 1, data)

        {packets, new_state} = Vampir.Packet.feed(pkt_state, data)

        for pkt <- packets do
          unless pkt.opcode in [16, 17, 20, 21] do
            IO.puts("[#{label}] #{Vampir.Packet.format_packet(pkt)}")
          end
          Vampir.Capture.store_packet(stream_id, label, pkt, pkt.raw)
        end

        game_relay_loop(src, dst, label, stream_id, new_state, chunk_seq + 1)

      {:error, _} ->
        :ok
    end
  end

  # --- Upstream: CONNECT through HTTP proxy ---

  defp handle_upstream(client, ip, port) do
    IO.puts("[upstream] #{ip}:#{port}")

    case :gen_tcp.connect(@upstream_host, @upstream_port, [:binary, packet: :raw, active: false]) do
      {:ok, upstream} ->
        connect_req =
          "CONNECT #{ip}:#{port} HTTP/1.1\r\n" <>
            "Host: #{ip}:#{port}\r\n" <>
            "Proxy-Authorization: Basic #{@upstream_auth}\r\n" <>
            "\r\n"

        :gen_tcp.send(upstream, connect_req)

        case :gen_tcp.recv(upstream, 0, 10_000) do
          {:ok, resp} ->
            [status_line | _] = String.split(resp, "\r\n", parts: 2)

            if String.contains?(status_line, "200") do
              relay(client, upstream)
            else
              IO.puts("[upstream] CONNECT rejected for #{ip}:#{port}: #{status_line}")
              :gen_tcp.close(client)
              :gen_tcp.close(upstream)
            end

          {:error, reason} ->
            IO.puts("[upstream] No response from proxy: #{reason}")
            :gen_tcp.close(client)
            :gen_tcp.close(upstream)
        end

      {:error, reason} ->
        IO.puts("[upstream] Connect to proxy failed: #{reason}")
        :gen_tcp.close(client)
    end
  end

  # --- Simple bidirectional relay ---

  defp relay(client, remote) do
    pid1 = spawn_link(fn -> relay_loop(client, remote) end)
    pid2 = spawn_link(fn -> relay_loop(remote, client) end)
    ref1 = Process.monitor(pid1)
    ref2 = Process.monitor(pid2)

    receive do
      {:DOWN, ^ref1, :process, _, _} -> :ok
      {:DOWN, ^ref2, :process, _, _} -> :ok
    end

    :gen_tcp.close(client)
    :gen_tcp.close(remote)
  end

  defp relay_loop(src, dst) do
    case :gen_tcp.recv(src, 0) do
      {:ok, data} ->
        :gen_tcp.send(dst, data)
        relay_loop(src, dst)

      {:error, _} ->
        :ok
    end
  end
end
