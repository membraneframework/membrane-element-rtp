defmodule Membrane.Element.RTP.PacketParser do
  @moduledoc """
  Parses RTP packet based on [RFC3550](https://tools.ietf.org/html/rfc3550#page-13)
  """

  alias Membrane.Element.RTP.{Header, HeaderExtension, Packet}

  @type error_reason() :: :wrong_version | :packet_malformed

  @spec parse_packet(binary()) :: {:ok, Packet.t()} | {:error, error_reason()}
  def parse_packet(<<version::2, _::6, _::binary>>) when version != 2,
    do: {:error, :wrong_version}

  def parse_packet(bytes) when byte_size(bytes) < 4 * 3, do: {:error, :packet_malformed}

  def parse_packet(
        <<v::2, p::1, x::1, cc::4, m::1, payload_type::7, sequence_number::16, timestamp::32,
          ssrc::32, rest::binary>>
      ) do
    {parsed_csrc, rest} = extract_csrcs(rest, cc)
    {extension_header, payload} = extract_extension_header(x, rest)
    payload = ignore_padding(p, payload)

    packet = %Packet{
      header: %Header{
        version: v,
        marker: extract_boolean(m),
        padding: extract_boolean(p),
        extension_header: extract_boolean(x),
        csrc_count: cc,
        ssrc: ssrc,
        sequence_number: sequence_number,
        payload_type: payload_type,
        timestamp: timestamp,
        csrcs: parsed_csrc,
        extension_header_data: extension_header
      },
      payload: payload
    }

    {:ok, packet}
  end

  def serialize(packet) do
    %{
      version: v,
      csrcs: csrc,
      csrc_count: cc,
      marker: marker,
      payload_type: pt,
      sequence_number: seq,
      timestamp: timestamp,
      ssrc: ssrc,
      # TODO support extension header
      extension_header: false
    } = packet.header

    x = 0
    # We don't need padding
    p = 0

    csrc_bin = serialize_csrcs(csrc)

    <<v::2, p::1, x::1, cc::4, encode_boolean(marker)::1, pt::7, seq::16, timestamp::32, ssrc::32,
      csrc_bin::binary, packet.payload::binary>>
  end

  defp serialize_csrcs(csrcs, acc \\ <<>>)

  defp serialize_csrcs([], acc) do
    acc
  end

  defp serialize_csrcs([csrc | csrcs], acc) do
    acc <> <<csrc::32>> <> serialize_csrcs(csrcs)
  end

  defp extract_csrcs(data, count, acc \\ [])
  defp extract_csrcs(data, 0, acc), do: {acc, data}

  defp extract_csrcs(<<csrc::32, rest::binary>>, count, acc),
    do: extract_csrcs(rest, count - 1, [csrc | acc])

  defp extract_extension_header(is_header_present, data)
  defp extract_extension_header(0, data), do: {nil, data}

  defp extract_extension_header(1, binary_data) do
    <<profile_specific::16, len::16, header_ext::binary-size(len), rest::binary>> = binary_data

    extension_data = %HeaderExtension{
      profile_specific: profile_specific,
      header_extension: header_ext
    }

    {extension_data, rest}
  end

  defp extract_boolean(read_value)
  defp extract_boolean(1), do: true
  defp extract_boolean(0), do: false

  defp encode_boolean(false), do: 0
  defp encode_boolean(true), do: 1

  defp ignore_padding(is_padding_present, payload)
  defp ignore_padding(0, payload), do: payload

  defp ignore_padding(1, payload) do
    padding_size = :binary.last(payload)
    payload_size = byte_size(payload) - padding_size
    <<stripped_payload::binary-size(payload_size), _::binary-size(padding_size)>> = payload
    stripped_payload
  end
end
