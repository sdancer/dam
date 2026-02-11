defmodule Vampir.GameState.World do
  @moduledoc "Visible world: nearby entities. Pure data."

  defstruct [
    # actor_id => %Entity{}
    entities: %{}
  ]
end
