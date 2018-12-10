defmodule Membrane.Element.RTP.Header do
  alias Membrane.Caps.RTP

  @typedoc """
  Describes data stored in RTP header.
  """

  @typedoc """
  This field identifies the version of RTP.  The version defined by this specification is two 2.
  """
  @type version :: 0..2

  @typedoc """
  """
  @type padding :: boolean()

  @type extension :: boolean()

  @type marker :: boolean()

  @type t :: %__MODULE__{
          version: version(),
          padding: padding(),
          extension_header: extension(),
          csrc_count: 0..15,
          ssrc: non_neg_integer(),
          marker: marker(),
          payload_type: binary(),
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
