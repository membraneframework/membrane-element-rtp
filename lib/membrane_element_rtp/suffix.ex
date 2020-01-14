defmodule Membrane.Element.RTP.Suffix do
  @moduledoc false

  @type t :: %__MODULE__{
          mki: non_neg_integer() | nil,
          auth_tag: binary() | nil
        }

  defstruct [
    :mki,
    :auth_tag
  ]
end
