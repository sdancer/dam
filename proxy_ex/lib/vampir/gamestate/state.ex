defmodule Vampir.GameState.State do
  @moduledoc "Root game state. Pure data — no logic."

  alias Vampir.GameState.{Connection, Player, World, Chat}

  defstruct [
    connection: %Connection{},
    player: %Player{},
    world: %World{},
    chat: %Chat{}
  ]
end
