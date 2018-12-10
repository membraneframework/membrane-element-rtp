defmodule Membrane.Element.RTP.ParserTest do
  use ExUnit.Case

  alias Membrane.Element.RTP.{Header, Packet, PacketParser, SamplePacket}

  describe "RTP parser" do
    test "parses valid packets" do
      assert PacketParser.parse_frame(SamplePacket.sample_packet()) ==
               {:ok,
                %Packet{
                  header: %Header{
                    csrc_count: 0,
                    csrcs: [],
                    extension_header: false,
                    marker: false,
                    padding: false,
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
    assert PacketParser.parse_frame(<<1::2, 1233::1022>>) == {:error, :wrong_version}
  end

  test "returns error when packet is too short" do
    assert PacketParser.parse_frame(<<128, 127, 0, 0, 1>>) == {:error, :packet_malformed}
  end
end
