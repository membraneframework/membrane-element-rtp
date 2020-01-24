defmodule Membrane.Element.RTP.Parser.Secure do
  @moduledoc false
  # Provides SRTP functionality for the element.

  use Bitwise

  @rollover_counter_limit 1 <<< 32
  @seq_limit 65536
  @seq_half 32768

  alias Membrane.Element.RTP.{Header, Suffix}
  alias Membrane.Element.RTP.Parser.Secure.{Context, MasterKey, SessionKeys}

  @spec get_context(%{Context.id_t() => Context.t()}, integer(), map()) ::
          {:ok, Context.t(), Context.id_t()}
  def get_context(context_map, ssrc, metadata) do
    id = {ssrc, metadata[:local_address], metadata[:local_port]}

    Map.get(context_map, id, nil)
    |> case do
      nil -> {:error, :no_context}
      ctx -> {:ok, ctx, id}
    end
  end

  @doc """
  Verifies (authenticates) and decrypts the payload of a SRTP packet.
  Returns the decrypted payload along with any updates that should be applied
  to the cryptographic context.
  """
  @spec process_payload(binary(), binary(), Context.t(), Header.t(), Suffix.t()) ::
          {:ok, binary(), Context.update_t()} | {:error, atom()}
  def process_payload(payload, auth_portion, context, header, suffix) do
    {index, s_l, roc} = get_packet_index(context, header.sequence_number)

    with {:ok, mki} <- get_mki(context, suffix, index),
         {context, keys} = SessionKeys.get_or_derive_session_keys(context, mki, index),
         :ok <- check_replayed(context.replay_list, index),
         :ok <- check_auth(context, keys, auth_portion, suffix.auth_tag) do
      payload =
        decrypt_payload(
          payload,
          context,
          keys.srtp_encr,
          keys.srtp_salt,
          header.ssrc,
          index
        )

      updates = {index, s_l, roc, mki}
      {:ok, payload, updates}
    end
  end

  @spec update_context(Context.t(), Context.update_t()) :: {:ok, Context.t()}
  def update_context(context, nil), do: {:ok, context}

  def update_context(context, {index, s_l, roc, mki}) do
    context
    |> Map.merge(%{s_l: s_l, rollover_counter: roc})
    |> update_mk_counter(mki)
    |> update_replay_list(index)
  end

  @spec get_packet_index(Context.t(), non_neg_integer()) ::
          {non_neg_integer(), non_neg_integer(), non_neg_integer()}
  defp get_packet_index(%Context{rollover_counter: roc, s_l: s_l}, seq) do
    # Get index - Appendix A
    # Update roc, s_l if necessary - page 13.

    {s_l, roc, v} =
      cond do
        s_l < @seq_half and seq - s_l > @seq_half ->
          {s_l, roc, rem(roc - 1, @rollover_counter_limit)}

        s_l >= @seq_half and s_l - @seq_half > seq ->
          v = rem(roc + 1, @rollover_counter_limit)
          {seq, v, v}

        seq > s_l ->
          {seq, roc, roc}

        true ->
          {s_l, roc, roc}
      end

    index = seq + v * @seq_limit
    {index, s_l, roc}
  end

  @spec get_mki(Context.t(), Suffix.t(), integer()) ::
          {:ok, MasterKey.id_t()} | {:error, :no_mki_found}
  defp get_mki(%Context{mki_indicator: true}, %Suffix{mki: mki}, _index) do
    {:ok, mki}
  end

  defp get_mki(%Context{from_to_list: from_tos, mki_indicator: false}, _suffix, index) do
    fits = fn {from, to, _} -> index in from..to end

    from_tos
    |> Enum.find(:error, fits)
    |> case do
      {_, _, mki} -> {:ok, mki}
      :error -> {:error, :no_mki_found}
    end
  end

  @spec check_replayed(list(), integer()) :: :ok | {:error, :replayed | :ignored}

  defp check_replayed(_replay_list, _index) do
    # TODO
    :ok
  end

  @spec check_auth(Context.t(), Context.session_keys_t(), binary(), binary()) ::
          :ok | {:error, :auth_tag_mismatch}
  defp check_auth(_ctx, _keys, _buffer, nil), do: :ok

  defp check_auth(
         %Context{rollover_counter: roc, auth_alg: :hmac_sha},
         %{srtp_auth: key},
         auth_portion,
         auth_tag
       ) do
    m = auth_portion <> <<roc::32>>

    :hmac
    |> :crypto.macN(:sha, key, m, 10)
    |> case do
      ^auth_tag -> :ok
      _ -> {:error, :auth_tag_mismatch}
    end
  end

  @spec decrypt_payload(
          data :: binary(),
          Context.t(),
          key :: binary(),
          salt :: binary(),
          ssrc :: integer(),
          packet_index :: integer()
        ) ::
          binary()
  defp decrypt_payload(data, %Context{encryption_alg: nil}, _, _, _, _), do: data

  defp decrypt_payload(data, %Context{encryption_alg: :aes_128_ctr}, key, salt, ssrc, index) do
    isalt = :binary.decode_unsigned(salt)
    iv = (isalt <<< 16) ^^^ (ssrc <<< 64) ^^^ (index <<< 16)
    iv = <<iv::128>>

    :crypto.crypto_one_time(:aes_128_ctr, key, iv, data, false)
  end

  @spec update_mk_counter(Context.t(), MasterKey.id_t()) :: Context.t()
  defp update_mk_counter(context, mki) do
    update_in(context, [:master_keys, mki, :packet_counter], &(&1 + 1))
  end

  @spec update_replay_list(Context.t(), integer()) :: {:ok, Context.t()}
  defp update_replay_list(%Context{replay_list: _list} = ctx, _todo_index) do
    # TODO
    {:ok, ctx}
  end
end
