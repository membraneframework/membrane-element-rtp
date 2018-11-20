defmodule Membrane.Element.RTP.ParserTest do
  use ExUnit.Case

  alias Membrane.Element.RTP.{Parser, SamplePacket}
  alias Membrane.Caps.RTP.Packet

  describe "RTP parser" do
    test "parses valid packets" do
      assert Membrane.Element.RTP.Parser.parse_frame(SamplePacket.sample_packet()) ==
               {:ok,
                %Packet{
                  header: %Packet.Header{
                    csrc_count: 0,
                    csrcs: [],
                    extension_header: nil,
                    marker: 0,
                    padding: 0,
                    payload_type: 14,
                    sequence_number: 3983,
                    ssrc: 3_919_876_492,
                    timestamp: 1_653_702_647,
                    version: 2
                  },
                  payload: SamplePacket.sample_packet_payload()
                }}
    end
  end

  test "returns error when version is not supported" do
    assert Parser.parse_frame(<<1::2, 1233::1022>>) == {:error, :wrong_version}
  end

  test "returns error when packet is too short" do
    assert Parser.parse_frame(<<128, 127, 0, 0, 1>>) == {:error, :packet_malformed}
  end
end
