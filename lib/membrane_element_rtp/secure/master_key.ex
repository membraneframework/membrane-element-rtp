defmodule Membrane.Element.RTP.Parser.Secure.MasterKey do
  @moduledoc """
  """

  @type session_keys_t() :: %{keys: map(), lifetime: integer()}

  @type t :: %__MODULE__{
          key: binary(),
          salt: binary(),
          key_derivation_rate: non_neg_integer(),
          packet_count: non_neg_integer(),
          session_keys: session_keys_t()
        }

  defstruct key: nil,
            salt: nil,
            key_derivation_rate: 0,
            packet_count: 0,
            session_keys: nil
end
