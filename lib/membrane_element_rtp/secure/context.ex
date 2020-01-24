defmodule Membrane.Element.RTP.Parser.Secure.Context do
  @moduledoc """
  A struct for a cryptographic context, along with types for some of its fields.
  """

  alias Membrane.Element.RTP.Parser.Secure.MasterKey

  @type authentication_algorithm_t() :: :hmac_sha
  @type encryption_algorithm_t() :: :aes_128_ctr | nil
  @type id_t() :: {MasterKey.id_t(), ip :: String.t(), port :: non_neg_integer()}
  @type session_keys_t() :: %{srtp_encr: binary(), srtp_auth: binary(), srtp_salt: binary()}
  @type session_t() :: {session_keys_t(), lifetime :: integer()}

  @type t() :: %__MODULE__{
          master_keys: %{MasterKey.id_t() => MasterKey.t()},
          from_to_list: [{from_position :: integer(), to_position :: integer(), MasterKey.id_t()}],
          sessions: %{MasterKey.id_t() => session_t()},
          rollover_counter: non_neg_integer(),
          encryption_alg: encryption_algorithm_t(),
          auth_alg: authentication_algorithm_t(),
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
  @type update_t() ::
          {non_neg_integer(), non_neg_integer(), non_neg_integer(), MasterKey.id_t()} | nil

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
