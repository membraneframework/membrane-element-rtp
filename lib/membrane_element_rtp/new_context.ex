defmodule Membrane.Event.NewContext do
  alias Membrane.Element.RTP.Secure.Context

  defstruct [:context_id, :context]

  @type t :: %__MODULE__{
          context_id: Context.id(),
          context: Context.t()
        }
end
