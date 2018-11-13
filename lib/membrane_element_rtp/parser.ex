defmodule Membrane.Element.RTP.Parser do
  alias Membrane.Element.RTP.Packet

  @moduledoc """
  Parses RTP packet base on [RFC3550](https://tools.ietf.org/html/rfc3550#page-13)
  """

  def parse_frame(
        <<v::2, p::1, x::1, cc::4, m::1, payload_type::7, sequence_number::16, timestamp::32,
          ssrc::32, rest::binary>> = whole_thing
      ) do
    {parsed_csrc, rest} = extract_crsrcs(rest, cc)
    {header, payload} = extract_extension_header(x, rest)

    %Packet{
      header: %Packet.Header{
        version: v,
        marker: m,
        padding: p,
        extension: x,
        csrc_count: cc,
        ssrc: ssrc,
        sequence_number: sequence_number,
        payload_type: payload_type,
        timestamp: timestamp
      },
      payload: payload
    }
  end

  def extract_crsrcs(data, count), do: doextract_crsrcs(data, count, [])

  defp doextract_crsrcs(data, 0, acc), do: {acc, data}

  defp doextract_crsrcs(<<csrc::32, rest::binary>>, count, acc),
    do: doextract_crsrcs(rest, count - 1, [csrc | acc])

  defp extract_extension_header(is_header_present, data)
  defp extract_extension_header(0, data), do: {nil, data}

  defp extract_extension_header(1, <<extension_header::32, rest::binary>>),
    do: {extension_header, rest}
end
