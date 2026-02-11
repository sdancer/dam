defmodule Vampir.DecoderTest do
  use ExUnit.Case

  setup_all do
    Application.ensure_all_started(:jason)
    Vampir.Opcodes.start_link([])
    Vampir.Decoder.start_link([])
    :ok
  end

  # [S->C] #196 [37B] op=608 PktSkillStartResult
  #   0000  00 00 00 00 01 C9 32 00 00 31 62 CD 47 14 70 03
  #   0010  48 00 00 00 00 A0 41 00 00 00 00 00 00
  #
  #  ┌─────────┬──────────────┬────────────────┬──────────────┐
  #  │ Offset  │    Field     │      Type      │    Value     │
  #  ├─────────┼──────────────┼────────────────┼──────────────┤
  #  │ [0:4]   │ _base        │ uint32         │ 0            │
  #  │ [4]     │ Result       │ int8           │ 1            │
  #  │ [5:9]   │ SkillInfoId  │ int32          │ 13,001       │
  #  │ [9:13]  │ TargetPosX   │ float          │ 105,156.38   │
  #  │ [13:17] │ TargetPosY   │ float          │ 134,592.31   │
  #  │ [17:19] │ ComboCount   │ uint16         │ 0            │
  #  │ [19:23] │ CoolTime     │ float          │ 0.0          │
  #  │ [23:25] │ ChangeList   │ TArray<struct> │ stops        │
  #  └─────────┴──────────────┴────────────────┴──────────────┘
  test "PktSkillStartResult (op=608) decodes fields from captured payload" do
    payload =
      <<0x00, 0x00, 0x00, 0x00,   # _base: uint32 = 0
        0x01,                     # Result: int8 = 1
        0xC9, 0x32, 0x00, 0x00,   # SkillInfoId: int32 LE = 13001
        0x31, 0x62, 0xCD, 0x47,   # TargetPosX: float = 105156.38
        0x14, 0x70, 0x03, 0x48,   # TargetPosY: float = 134592.31
        0x00, 0x00,               # ComboCount: uint16 = 0
        0x00, 0x00, 0xA0, 0x41,   # CoolTime: float = 20.0
        0x00, 0x00, 0x00, 0x00,   # ChangeList: TArray -> stops
        0x00>>

    assert {:ok, fields} = Vampir.Decoder.decode_fields(608, payload)
    fields_map = Map.new(fields)

    assert fields_map["_base"] == 0
    assert fields_map["Result"] == 1
    assert fields_map["SkillInfoId"] == 13_001

    assert_in_delta fields_map["TargetPosX"], 105_156.38, 0.01
    assert_in_delta fields_map["TargetPosY"], 134_592.31, 0.01

    assert fields_map["ComboCount"] == 0
    assert_in_delta fields_map["CoolTime"], 20.0, 0.01

    # ChangeList is TArray<struct> -> stops with remaining bytes
    assert {"ChangeList", {:remaining, _rest}} = Enum.find(fields, fn {k, _} -> k == "ChangeList" end)
  end
end
