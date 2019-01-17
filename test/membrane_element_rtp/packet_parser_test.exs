defmodule Membrane.Element.RTP.PacketParserTest do
  use ExUnit.Case

  alias Membrane.Element.RTP.{Header, Packet, PacketParser, SamplePacket}

  describe "RTP parser" do
    test "parses valid packets" do
      assert PacketParser.parse_packet(SamplePacket.sample_packet()) ==
               {:ok,
                %Packet{
                  header: SamplePacket.sample_header(),
                  payload: SamplePacket.sample_packet_payload()
                }}
    end

    test "returns error when version is not supported" do
      assert PacketParser.parse_packet(<<1::2, 1233::1022>>) == {:error, :wrong_version}
    end

    test "returns error when packet is too short" do
      assert PacketParser.parse_packet(<<128, 127, 0, 0, 1>>) == {:error, :packet_malformed}
    end

    test "parses csrcs correctly" do
      <<header_1::4, _old_cc::4, header_2::88, payload::binary()>> = SamplePacket.sample_packet()
      test_packet = <<header_1::4, 2::4, header_2::88, 12::32, 21::32, payload::binary()>>
      expected_header = %Header{SamplePacket.sample_header() | csrcs: [21, 12], csrc_count: 2}

      assert PacketParser.parse_packet(test_packet) ==
               {:ok,
                %Packet{
                  header: expected_header,
                  payload: SamplePacket.sample_packet_payload()
                }}
    end

    test "ignores padding" do
      test_padding_size = 8
      padding_octets = test_padding_size - 1
      test_padding = <<0::size(padding_octets)-unit(8), test_padding_size::size(1)-unit(8)>>
      <<version::2, _padding::1, header_1::5, rest::binary>> = SamplePacket.sample_packet()
      payload_size = byte_size(rest)

      test_packet =
        <<version::2, 1::1, header_1::5, rest::binary-size(payload_size),
          test_padding::binary-size(test_padding_size)>>

      expected_header = %Header{SamplePacket.sample_header() | padding: true}

      assert PacketParser.parse_packet(test_packet) ==
               {:ok,
                %Packet{
                  header: expected_header,
                  payload: SamplePacket.sample_packet_payload()
                }}
    end

    test "reads extension header" do
      extension_header = <<0::16, 4::16, 254::32>>

      expected_parsed_extension_header = %Membrane.Element.RTP.HeaderExtension{
        header_extension: <<254::32>>,
        profile_specific: 0
      }

      # Extension is stored on 4th bit of header
      <<header_1::3, _extension::1, header_2::92, payload::binary>> = SamplePacket.sample_packet()

      # Glueing data back together with extension header in place
      test_packet =
        <<header_1::3, 1::1, header_2::92, extension_header::binary-size(8), payload::binary>>

      expected_header = %Header{
        SamplePacket.sample_header()
        | extension_header: true,
          extension_header_data: expected_parsed_extension_header
      }

      assert PacketParser.parse_packet(test_packet) ==
               {:ok,
                %Membrane.Element.RTP.Packet{
                  header: expected_header,
                  payload: SamplePacket.sample_packet_payload()
                }}
    end
  end
end
