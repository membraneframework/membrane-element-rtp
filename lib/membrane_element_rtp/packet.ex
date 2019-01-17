defmodule Membrane.Element.RTP.Packet do
  @moduledoc """
  Describes an RTP packet.
  """

  alias Membrane.Element.RTP.Header

  @type t :: %__MODULE__{
          header: Header.t(),
          payload: binary()
        }

  defstruct [
    :header,
    :payload
  ]
end
