defmodule Vampir.GameState.Connection do
  @moduledoc "Connection/session state. Pure data."

  defstruct [
    # :disconnected | :version | :login | :character_select | :in_game
    phase: :disconnected,
    account: nil,
    user_id: nil,
    server_id: nil,
    client_version: nil,
    packet_version: nil,
    # Latest ping round-trip
    last_ping_tick: nil,
    last_ping_result: nil
  ]
end
