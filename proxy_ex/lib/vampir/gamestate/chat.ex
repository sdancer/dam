defmodule Vampir.GameState.Chat do
  @moduledoc "Chat message log. Pure data."

  # Single chat message
  defmodule Message do
    defstruct [
      channel: nil,     # :world | :party | :guild | :whisper | :system | atom
      sender_id: nil,
      sender_name: nil,
      text: nil,
      timestamp: nil    # monotonic or server time
    ]
  end

  defstruct [
    # Recent messages, newest first, capped by controller
    messages: []
  ]
end
