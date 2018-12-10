defmodule Membrane.Element.RTP.SamplePacket do
  alias Membrane.Element.RTP.Header

  @external_resource "test/fixtures/rtp/rtp_packet.bin"
  @sample_packet File.read!("test/fixtures/rtp/rtp_packet.bin")
  @external_resource "test/fixtures/rtp/rtp_packet_payload.bin"
  @sample_packet_payload File.read!("test/fixtures/rtp/rtp_packet_payload.bin")

  def sample_packet, do: @sample_packet
  def sample_packet_payload, do: @sample_packet_payload

  def sample_buffer,
    do: %Membrane.Buffer{
      payload: sample_packet_payload(),
      metadata: %{
        rtp_header: sample_header()
      }
    }

  def sample_header,
    do: %Header{
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
    }
end
