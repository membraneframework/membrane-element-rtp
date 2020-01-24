defmodule Membrane.Element.RTP.PacketParser do
  @moduledoc """
  Parses RTP and parts of SRTP packets based on [RFC3550](https://tools.ietf.org/html/rfc3550#page-13) and [RFC3711](https://tools.ietf.org/html/rfc3711#page-6)
  """

  alias Membrane.Element.RTP.{Header, HeaderExtension, Packet, Suffix}

  @type error_reason_t() :: :wrong_version | :packet_malformed

  @spec parse_packet(binary()) :: {:ok, Packet.t()} | {:error, error_reason_t()}
  def parse_packet(packet)

  def parse_packet(<<version::2, _::6, _::binary>>) when version != 2,
    do: {:error, :wrong_version}

  def parse_packet(bytes) when byte_size(bytes) < 4 * 3,
    do: {:error, :packet_malformed}

  def parse_packet(packet) do
    {header, rest} = parse_header(packet)
    {payload, suffix} = extract_suffix(rest, false, 0)
    payload = ignore_padding(payload, header.padding)

    packet = %Packet{
      header: header,
      payload: payload,
      suffix: suffix
    }

    {:ok, packet}
  end

  @spec parse_header(binary()) :: {Header.t(), binary()}
  def parse_header(
        <<v::2, p::1, x::1, cc::4, m::1, payload_type::7, sequence_number::16, timestamp::32,
          ssrc::32, rest::binary>>
      ) do
    {parsed_csrc, rest} = extract_csrcs(rest, cc)
    {extension_header, rest} = extract_extension_header(x, rest)

    header = %Header{
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
    }

    {header, rest}
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

  @spec extract_suffix(binary(), boolean(), non_neg_integer()) :: {binary(), binary()}
  def extract_suffix(payload_and_suffix, mki_indicator, n_tag) do
    n_tag = div(n_tag, 8)
    l = byte_size(payload_and_suffix) - n_tag - if(mki_indicator, do: 4, else: 0)
    <<payload::binary-size(l), suffix::binary>> = payload_and_suffix

    suffix =
      case {mki_indicator, n_tag} do
        {false, 0} ->
          nil

        {false, _} ->
          %Suffix{mki: nil, auth_tag: suffix}

        {true, 0} ->
          %Suffix{mki: suffix, auth_tag: nil}

        {true, _} ->
          <<mki::32, auth_tag::binary-size(n_tag)>> = suffix
          %Suffix{mki: mki, auth_tag: auth_tag}
      end

    {payload, suffix}
  end

  defp extract_boolean(read_value)
  defp extract_boolean(1), do: true
  defp extract_boolean(0), do: false

  @spec ignore_padding(binary(), boolean()) :: binary()
  def ignore_padding(payload, is_padding_present)
  def ignore_padding(payload, false), do: payload

  def ignore_padding(payload, true) do
    padding_size = :binary.last(payload)
    payload_size = byte_size(payload) - padding_size
    <<stripped_payload::binary-size(payload_size), _::binary-size(padding_size)>> = payload
    stripped_payload
  end
end
