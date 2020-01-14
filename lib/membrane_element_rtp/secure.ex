defmodule Membrane.Element.RTP.Secure do
  @moduledoc """
  Provides SRTP functionality for the element.
  """

  use Bitwise

  alias Membrane.Buffer
  alias Membrane.Element.RTP.{Packet, PacketParser, Suffix}
  alias Membrane.Element.RTP.Secure.{Context, SessionKeys}

  @spec get_context(map(), binary()) :: {:ok, Context.t(), Context.id()}

  def get_context(context_map, buffer) do
    # To parse a packet we need to know the cryptographic context it belongs to,
    # so we need to know its ssrc which is part of crypto context identificator.
    # That's why this gets ssrc out of the raw payload, before any parsing is done.
    <<_::64, ssrc::32, _::binary>> = buffer

    id = {ssrc, buffer.metadata[:local_address], buffer.metadata[:local_port]}
    context = Map.get(context_map, id, nil)
    {:ok, context, id}
  end

  @spec process_buffer(Context.t(), Buffer.t()) ::
          {:ok, Packet.t(), Context.update()} | {:error, any()}

  @doc """
  Verifies (authenticates) and decrypts a packet (buffer). Returns the packet along
  with any updates that should be applied to the cryptographic context.

  This might be used by key estabilishment protocols like DTLS-SRTP (and discard the updates).
  """
  def process_buffer(context, buffer) do
    with {:ok, packet} <-
           PacketParser.parse_packet(buffer.payload,
             srtp: true,
             mki_indicator: context.mki_indicator,
             auth_tag_size: context.auth_tag_size
           ),
         {index, s_l, roc} <- get_packet_index(context, packet.header.sequence_number),
         {:ok, mki} <- get_mki(context, packet, index),
         {context, keys} <- SessionKeys.get_or_derive_session_keys(context, mki, index),
         :ok <- check_replayed(context.replay_list, index),
         :ok <- check_auth(context, buffer.payload, packet.suffix.auth_tag),
         {:ok, payload} <-
           decrypt_payload(
             packet.payload,
             context,
             keys.srtp_encr,
             keys.srtp_salt,
             packet.header.ssrc,
             index
           ),
         payload <- ignore_padding(payload, packet.header.padding) do
      packet = Map.put(packet, :buffer, payload)

      updates = {index, s_l, roc, mki}
      {:ok, packet, updates}
    end
  end

  @spec update_context(Context.t(), Context.update()) :: {:ok, Context.t(), Context.update()}

  def update_context(context, nil), do: context

  def update_context(context, {index, s_l, roc, mki}) do
    context
    |> Map.merge(%{s_l: s_l, rollover_counter: roc})
    |> update_mk_counter(mki)
    |> update_replay_list(index)
  end

  @spec get_packet_index(Context.t(), integer()) :: {integer(), integer(), integer()}

  defp get_packet_index(%Context{rollover_counter: roc, s_l: s_l}, seq) do
    int_limit = 1 <<< 32

    # Get index - Appendix A
    # Update roc, s_l if necessary - page 13.

    {s_l, roc, v} =
      cond do
        s_l < 32768 and seq - s_l > 32768 ->
          {s_l, roc, rem(roc - 1, int_limit)}

        s_l >= 32768 and s_l - 32768 > seq ->
          v = rem(roc + 1, int_limit)
          {seq, v, v}

        seq > s_l ->
          {seq, roc, roc}

        true ->
          {s_l, roc, roc}
      end

    index = seq + v * 65536
    {index, s_l, roc}
  end

  @spec get_mki(Context.t(), Packet.t(), integer()) :: {:ok, Context.mki()} | {:error, :atom}

  defp get_mki(%Context{mki_indicator: true}, %Packet{suffix: %Suffix{mki: mki}}, _) do
    {:ok, mki}
  end

  defp get_mki(%Context{from_to_list: from_tos, mki_indicator: false}, _, index) do
    fits = fn {from, to, _} -> from <= index and index <= to end

    from_tos
    |> Enum.find(:error, fits)
    |> case do
      {_, _, mki} -> {:ok, mki}
      :error -> {:error, :no_mki_found}
    end
  end

  @spec check_replayed(list(), integer()) :: :ok | :error

  defp check_replayed(_replay_list, _index) do
    # TODO
    :ok
  end

  @spec check_auth(Context.t(), binary(), binary()) :: :ok | {:error, :atom}

  defp check_auth(_, _, nil), do: :ok

  defp check_auth(context, buffer, auth_tag) do
    mki_size = if(context.mki_indicator, do: 4, else: 0)
    auth_portion_size = byte_size(buffer) - mki_size - div(context.auth_tag_size, 8)

    <<auth_portion::binary-size(auth_portion_size), _::binary>> = buffer

    %{srtp_auth: key} = context.session.keys

    calc_auth(
      context,
      key,
      auth_portion,
      auth_tag
    )
  end

  @spec calc_auth(Context.t(), binary(), binary(), binary()) :: :ok | {:error, :atom}

  defp calc_auth(
         %Context{rollover_counter: roc, auth_alg: :hmac_sha},
         key,
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

  @spec decrypt_payload(binary(), Context.t(), binary(), binary(), integer(), integer()) ::
          {:ok, binary()}

  defp decrypt_payload(data, %Context{encryption_alg: nil}, _, _, _, _), do: {:ok, data}

  defp decrypt_payload(data, %Context{encryption_alg: :aes_128_ctr}, key, salt, ssrc, index) do
    isalt = :binary.decode_unsigned(salt)
    iv = (isalt <<< 16) ^^^ (ssrc <<< 64) ^^^ (index <<< 16)
    iv = <<iv::128>>

    encrypted = :crypto.crypto_one_time(:aes_128_ctr, key, iv, data, false)

    {:ok, encrypted}
  end

  @spec ignore_padding(binary(), boolean()) :: binary()

  defp ignore_padding(payload, is_padding_present)
  defp ignore_padding(payload, false), do: payload

  defp ignore_padding(payload, true) do
    padding_size = :binary.last(payload)
    payload_size = byte_size(payload) - padding_size
    <<stripped_payload::binary-size(payload_size), _::binary-size(padding_size)>> = payload
    stripped_payload
  end

  def update_mk_counter(context, mki) do
    mk =
      context.master_keys
      |> Map.get(mki)
      |> Map.update!(:packet_counter, &(&1 + 1))

    put_in(context, [:master_keys, mki], mk)
  end

  @spec update_replay_list(Context.t(), integer()) :: {:ok, Context.t()}

  defp update_replay_list(%Context{replay_list: list} = ctx, _todo_index) do
    {:ok, %{ctx | replay_list: list}}
  end
end
