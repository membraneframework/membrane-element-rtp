defmodule Membrane.Element.RTP.Packet do
  @moduledoc """
  Describes an RTP packet.
  """

  alias Membrane.Element.RTP.{Header, Suffix}

  @type t :: %__MODULE__{
          header: Header.t(),
          payload: binary(),
          suffix: Suffix.t()
        }

  defstruct [
    :header,
    :payload,
    :suffix
  ]
end
