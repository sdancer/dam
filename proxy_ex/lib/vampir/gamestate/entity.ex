defmodule Vampir.GameState.Entity do
  @moduledoc "A visible entity (other player, NPC, mob). Pure data."

  defstruct [
    actor_id: nil,
    # :character | :npc | :unknown
    kind: :unknown,
    name: nil,
    level: nil,
    pos: nil,        # {x, y, z} or nil
    hp: nil,
    max_hp: nil,
    alive: true
  ]
end
