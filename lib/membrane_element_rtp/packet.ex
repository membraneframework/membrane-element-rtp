defmodule Membrane.Element.RTP.Packet do
  alias __MODULE__
  alias Membrane.Element.RTP.Header

  @type t :: %Packet{
          header: Header.t(),
          payload: any()
        }

  defstruct [
    :header,
    :payload
  ]
end
