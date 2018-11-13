defmodule Membrane.Element.RTP.Parser do
  alias Membrane.Element.RTP.Packet

  @moduledoc """
  Parses RTP packet base on [RFC3550](https://tools.ietf.org/html/rfc3550#page-13)
  """

  def parse_frame(<<2::2, _::binary>>), do: {:ok, :wrong_version}
  def parse_frame(bytes) when byte_size(bytes) < 32 * 3, do: {:ok, :packet_malformed}

  def parse_frame(
        <<v::2, p::1, x::1, cc::4, m::1, payload_type::7, sequence_number::16, timestamp::32,
          ssrc::32, rest::binary>>
      ) do
    {parsed_csrc, rest} = extract_csrcs(rest, cc)
    {extension_header, payload} = extract_extension_header(x, rest)

    packet = %Packet{
      header: %Packet.Header{
        version: v,
        marker: m,
        padding: p,
        extension_header: extension_header,
        csrc_count: cc,
        ssrc: ssrc,
        sequence_number: sequence_number,
        payload_type: payload_type,
        timestamp: timestamp,
        csrcs: parsed_csrc
      },
      payload: payload
    }

    {:ok, packet}
  end

  def extract_csrcs(data, count), do: doextract_csrcs(data, count, [])

  defp doextract_csrcs(data, 0, acc), do: {acc, data}

  defp doextract_csrcs(<<csrc::32, rest::binary>>, count, acc),
    do: doextract_csrcs(rest, count - 1, [csrc | acc])

  defp extract_extension_header(is_header_present, data)
  defp extract_extension_header(0, data), do: {nil, data}

  defp extract_extension_header(1, <<extension_header::32, rest::binary>>),
    do: {extension_header, rest}
end
