defmodule Membrane.Element.RTP.Packet do
  @moduledoc """
  Describes an RTP packet.
  """

  alias Membrane.Element.RTP.Header

  @type t :: %__MODULE__{
          header: Header.t(),
          payload: any()
        }

  defstruct [
    :header,
    :payload
  ]
end
