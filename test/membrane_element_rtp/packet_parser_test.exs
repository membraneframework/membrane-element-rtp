defmodule Membrane.Element.RTP.PacketParserTest do
  use ExUnit.Case

  alias Membrane.Element.RTP.{Header, PacketParser, SamplePacket, Suffix}

  describe "RTP.Parser for RTP packets" do
    test "parses valid packets" do
      assert PacketParser.parse_header(SamplePacket.sample_packet()) ==
               {:ok, SamplePacket.sample_header(), SamplePacket.sample_packet_payload()}
    end

    test "returns error when version is not supported" do
      assert PacketParser.parse_header(<<1::2, 1233::1022>>) == {:error, :wrong_version}
    end

    test "returns error when packet is too short" do
      assert PacketParser.parse_header(<<128, 127, 0, 0, 1>>) == {:error, :packet_malformed}
    end

    test "parses csrcs correctly" do
      <<header_1::4, _old_cc::4, header_2::88, payload::binary()>> = SamplePacket.sample_packet()
      test_packet = <<header_1::4, 2::4, header_2::88, 12::32, 21::32, payload::binary()>>
      expected_header = %Header{SamplePacket.sample_header() | csrcs: [21, 12], csrc_count: 2}

      assert PacketParser.parse_header(test_packet) ==
               {:ok, expected_header, SamplePacket.sample_packet_payload()}
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

      assert {:ok, ^expected_header, payload} = PacketParser.parse_header(test_packet)
      payload = PacketParser.ignore_padding(payload, true)
      assert payload == SamplePacket.sample_packet_payload()
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

      assert PacketParser.parse_header(test_packet) ==
               {:ok, expected_header, SamplePacket.sample_packet_payload()}
    end
  end

  describe "RTP.Parser for SRTP packets" do
    setup do
      test_binary = SamplePacket.sample_srtp_packet()
      {:ok, _hd, rest} = PacketParser.parse_header(test_binary)
      %{packet: test_binary, payload_and_suffix: rest}
    end

    test "parses SRTP suffixes", %{payload_and_suffix: rest} do
      {_payload, suffix} = PacketParser.extract_suffix(rest, false, 80)
      assert %Suffix{mki: nil, auth_tag: _} = suffix
    end

    test "parses SRTP suffixes with MKI", %{packet: packet, payload_and_suffix: rest} do
      s = byte_size(packet) - 20 - 4
      <<_::s*8, mki::32, tag::160>> = packet
      tag = :binary.encode_unsigned(tag)

      assert {_payload, suffix} = PacketParser.extract_suffix(rest, true, 160)
      assert %Suffix{mki: ^mki, auth_tag: ^tag} = suffix
    end
  end
end
