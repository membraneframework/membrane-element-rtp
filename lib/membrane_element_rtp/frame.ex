defmodule Membrane.Element.RTP.Frame do
  defstruct [
    :version,
    :padding,
    :extension,
    :csrc_count,
    :ssrc,
    :marker,
    :payload_type,
    :payload,
    :timestamp,
    :sequence_number
  ]
end
