defmodule Membrane.Event.NewContext do
  @moduledoc """
  This event means that a new cryptographic context should be added to the state of RTP.Parser.
  """
  alias Membrane.Element.RTP.Parser.Secure.Context

  defstruct [:context_id, :context]

  @type t :: %__MODULE__{
          context_id: Context.id_t(),
          context: Context.t()
        }
end
