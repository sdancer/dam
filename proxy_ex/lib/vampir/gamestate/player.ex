defmodule Vampir.GameState.Player do
  @moduledoc "Own character state. Pure data."

  defstruct [
    character_id: nil,
    name: nil,
    level: nil,
    class_id: nil,
    pos: nil,        # {x, y, z} or nil
    hp: nil,
    max_hp: nil,
    mp: nil,
    max_mp: nil,
    alive: true
  ]
end
