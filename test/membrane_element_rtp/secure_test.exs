defmodule Membrane.Element.RTP.Parser.Secure.SecureTest do
  use ExUnit.Case

  alias Membrane.Element.RTP.SamplePacket
  alias Membrane.Element.RTP.PacketParser
  alias Membrane.Element.RTP.Parser.Secure
  alias Membrane.Element.RTP.Parser.Secure.{Context, MasterKey}

  use Bitwise

  test("parses srtp packets") do
    tp = SamplePacket.sample_srtp_packet()

    key = <<1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
    salt = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>

    mk = %MasterKey{
      key: key,
      salt: salt,
      key_derivation_rate: 0
    }

    context = %Context{from_to_list: [{0, 42000, 0}], master_keys: %{0 => mk}}

    {:ok, header, rest} = PacketParser.parse_header(tp)
    {payload, suffix} = PacketParser.extract_suffix(rest, false, 80)
    {auth_portion, _} = PacketParser.extract_suffix(tp, false, 80)

    assert {:ok, result, _updates} =
             Secure.process_payload(payload, auth_portion, context, header, suffix)
  end
end
