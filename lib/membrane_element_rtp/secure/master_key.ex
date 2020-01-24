defmodule Membrane.Element.RTP.Parser.Secure.MasterKey do
  @moduledoc """
  A struct for a master key-salt pair.
  """

  @type id_t() :: non_neg_integer()

  @type t :: %__MODULE__{
          key: binary(),
          salt: binary(),
          key_derivation_rate: non_neg_integer(),
          packet_count: non_neg_integer()
        }

  defstruct key: nil,
            salt: nil,
            key_derivation_rate: 0,
            packet_count: 0
end
