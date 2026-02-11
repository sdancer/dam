defmodule VampirTest do
  use ExUnit.Case
  doctest Vampir

  test "greets the world" do
    assert Vampir.hello() == :world
  end
end
