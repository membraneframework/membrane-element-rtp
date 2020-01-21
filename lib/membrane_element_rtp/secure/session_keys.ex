defmodule Membrane.Element.RTP.Parser.Secure.SessionKeys do
  @moduledoc """
  Functions for retrieving/deriving SRTP session keys.

  Lifetime is the last index when the paired session keys are valid.
  nil lifetime means the session key never needs refresing (KDR equals 0)

  When a packet needs processing we check if session keys are valid and use them or
  derive a new set.

  TODO implement storing past session keys, in case packets arrive out of order
  """

  use Bitwise

  alias Membrane.Element.RTP.Parser.Secure.{Context, MasterKey}

  @key_types [:srtp_encr, :srtp_auth, :srtp_salt]
             |> Enum.with_index()
             |> Map.new()

  @spec get_or_derive_session_keys(Context.t(), Context.mki(), integer() | nil) ::
          {Context.t(), Context.session_keys()}

  def get_or_derive_session_keys(%Context{sessions: sessions} = ctx, mki, index) do
    sessions
    |> Map.get(mki)
    |> case do
      {sk, nil} -> {ctx, sk}
      {sk, until} when index < until -> {ctx, sk}
      _ -> derive_all_session_keys(ctx, mki, index)
    end
  end

  defp derive_all_session_keys(context, mki, index) do
    master_key = context.master_keys[mki]

    keys =
      Map.new(
        @key_types,
        fn {type, type_index} ->
          session_key = derive_session_key(master_key, index, context, type_index)
          {type, session_key}
        end
      )

    lifetime =
      case master_key.key_derivation_rate do
        0 -> nil
        kdr -> index + kdr
      end

    context = put_in(context.sessions[mki], {keys, lifetime})
    {context, keys}
  end

  defp derive_session_key(
         %MasterKey{key: key, salt: salt, key_derivation_rate: kdr},
         index,
         context,
         key_type
       ) do
    r = rfc_div(index, kdr)
    key_id = <<key_type::8>> <> <<r::48>>
    ikey_id = :binary.decode_unsigned(key_id)
    isalt = :binary.decode_unsigned(salt)
    ix = ikey_id ^^^ isalt

    iv = <<ix::112, 0, 0>>

    key_size =
      case key_type do
        0 -> context.encryption_key_size
        1 -> context.auth_key_size
        2 -> context.salt_size
      end

    data = <<0::size(key_size)>>

    :crypto.crypto_one_time(:aes_128_ctr, key, iv, data, true)
  end

  @spec rfc_div(integer(), integer()) :: integer()

  # rfc_div is defined on rfc 3711 page 27
  defp rfc_div(_, 0), do: 0
  defp rfc_div(a, b), do: div(a, b)
end
