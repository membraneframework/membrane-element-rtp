defmodule Membrane.Event.NewContext do
  alias Membrane.Element.RTP.Parser.Secure.Context

  defstruct [:context_id, :context]

  @type t :: %__MODULE__{
          context_id: Context.id_t(),
          context: Context.t()
        }
end
