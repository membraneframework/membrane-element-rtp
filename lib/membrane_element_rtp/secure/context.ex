defmodule Membrane.Element.RTP.Secure.Context do
  @moduledoc """
  A struct for a cryptographic context, along with types for some of its fields.
  """

  @type authentication_algorithm() :: :hmac_sha
  @type encryption_algorithm() :: :aes_128_ctr | nil
  @type id() :: {mki(), String.t(), non_neg_integer()}
  @type mki() :: non_neg_integer()

  @type t() :: %__MODULE__{
          master_keys: %{mki() => MasterKey.t()},
          from_to_list: [{integer(), integer(), mki()}],
          rollover_counter: non_neg_integer(),
          encryption_alg: encryption_algorithm(),
          auth_alg: authentication_algorithm(),
          auth_key_size: non_neg_integer(),
          auth_tag_size: non_neg_integer(),
          mki_indicator: boolean(),
          s_l: non_neg_integer(),
          replay_list: list(),
          encryption_key_size: non_neg_integer(),
          master_key_identifier_size: non_neg_integer(),
          salt_size: non_neg_integer()
        }

  @typedoc """
  Data needed to update a context after a packet has been parsed successfully.
  """
  @type update() :: {non_neg_integer(), non_neg_integer(), non_neg_integer(), mki()} | nil

  defstruct master_keys: %{},
            from_to_list: [],
            sessions: %{},
            rollover_counter: 0,
            encryption_alg: :aes_128_ctr,
            auth_alg: :hmac_sha,
            auth_key_size: 160,
            auth_tag_size: 80,
            mki_indicator: false,
            s_l: 0,
            replay_list: [],
            encryption_key_size: 128,
            master_key_identifier_size: 0,
            salt_size: 112
end
