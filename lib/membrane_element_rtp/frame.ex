defmodule Membrane.Element.RTP.Packet do
  defstruct [
    :header,
    :payload
  ]

  defmodule Header do
    defstruct [
      :version,
      :padding,
      :extension,
      :csrc_count,
      :ssrc,
      :marker,
      :payload_type,
      :timestamp,
      :sequence_number
    ]
  end
end
