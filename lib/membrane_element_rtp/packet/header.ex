defmodule Membrane.Element.RTP.Packet.Header do
  alias __MODULE__

  @type t :: %Header{
          version: 0..2,
          padding: 0..1,
          extension_header: 0..1,
          csrc_count: 0..15,
          ssrc: non_neg_integer(),
          marker: 0..1,
          payload_type: 0..255,
          timestamp: non_neg_integer(),
          sequence_number: non_neg_integer(),
          csrcs: [non_neg_integer()]
        }

  defstruct [
    :version,
    :padding,
    :extension_header,
    :csrc_count,
    :ssrc,
    :marker,
    :payload_type,
    :timestamp,
    :sequence_number,
    :csrcs
  ]
end
