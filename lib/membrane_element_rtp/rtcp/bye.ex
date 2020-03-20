defmodule Membrane.Element.RTP.RTCP.Bye do
  @moduledoc """
  Parses and constructs RTCP BYE packets defined in
  [RFC3550](https://tools.ietf.org/html/rfc3550#section-6.6)
  """
  use Bunch

  @type t :: %__MODULE__{
          ssrcs: [non_neg_integer()],
          reason: String.t() | nil
        }

  defstruct [:ssrcs, :reason]

  alias Membrane.Element.RTP.RTCP

  def to_binary(%{ssrcs: ssrcs, reason: reason}) do
    count = ssrcs |> length()
    ssrcs = ssrcs |> Enum.map(&<<&1::32>>) |> Enum.join()

    reason =
      case reason do
        nil ->
          <<>>

        other ->
          length = String.length(other)
          <<length::8, other::binary>>
      end

    body = ssrcs <> reason
    length = RTCP.calc_length(body)

    header = <<2::2, 0::1, count::5, 203::8, length::16>>

    header <> body
  end

  def parse(packet, count) do
    ssrcs_size = count * 4
    <<ssrcs::binary-size(ssrcs_size), reason::binary>> = packet

    ssrcs =
      ssrcs
      |> Bunch.Binary.chunk_every(4)
      |> Enum.map(&:binary.decode_unsigned(&1))

    result = %__MODULE__{ssrcs: ssrcs, reason: make_reason(reason)}
    {:ok, result}
  end

  defp make_reason(<<>>), do: nil
  defp make_reason(<<_length::8, reason::binary>>), do: reason
end
