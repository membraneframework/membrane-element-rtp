defmodule Membrane.Element.RTP.Parser do
  @moduledoc """
  Parses RTP or SRTP packets, depending on provided options.
  """

  use Membrane.Filter

  alias Membrane.Buffer
  alias Membrane.Caps.RTP, as: Caps
  alias Membrane.Element.Action
  alias Membrane.Element.RTP.Parser.Secure
  alias Membrane.Element.RTP.Parser.Secure.Context
  alias Membrane.Element.RTP.{Header, Packet, PacketParser, PayloadTypeDecoder, Suffix}

  @metadata_fields [:timestamp, :sequence_number, :ssrc, :payload_type]

  def_options context: [
                spec: Context.t(),
                description: "Initial map with cryptographic contexts",
                default: %{}
              ],
              secure: [
                spec: boolean(),
                description: "Enables SRTP support",
                default: false
              ]

  def_output_pad :output,
    caps: Caps

  def_input_pad :input,
    caps: :any,
    demand_unit: :buffers

  defmodule State do
    @moduledoc false
    defstruct raw_payload_type: nil,
              secure: false,
              context: nil

    @type t :: %__MODULE__{
            raw_payload_type: Caps.raw_payload_type() | nil,
            secure: boolean(),
            context: nil | Context.t()
          }
  end

  @impl true
  def handle_init(opts) do
    {:ok, %State{secure: opts.secure, context: opts.context}}
  end

  @impl true
  def handle_event(:input, event, _ctx, state) do
    {{:ok, event: {:output, event}}, state}
  end

  @impl true
  def handle_event(:output, event, _ctx, state) do
    {{:ok, event: {:input, event}}, state}
  end

  @impl true
  def handle_process(:input, buffer, _ctx, state) do
    buffer
    |> process_buffer(state)
    |> case do
      {:ok, packet, state} ->
        {commands, state} = build_commands(packet, buffer, state)
        {{:ok, commands}, state}

      {:error, reason} ->
        {{:error, reason}, state}
    end
  end

  @impl true
  def handle_demand(:output, size, _unit, _ctx, state) do
    {{:ok, demand: {:input, size}}, state}
  end

  @spec process_buffer(Buffer.t(), State.t()) ::
          {:ok, Packet.t(), State.t()} | {:error, atom()}
  defp process_buffer(buffer, state) do
    with {:ok, header, payload} <- PacketParser.parse_header(buffer.payload),
         {:ok, payload, suffix, state} <- process_secure(buffer, header, payload, state) do
      payload = PacketParser.ignore_padding(payload, header.padding)

      packet = %Packet{
        header: header,
        payload: payload,
        suffix: suffix
      }

      {:ok, packet, state}
    end
  end

  @spec process_secure(Buffer.t(), Header.t(), binary(), State.t()) ::
          {:ok, binary(), Suffix.t() | nil, State.t()} | {:error, atom()}
  defp process_secure(_buffer, _header, payload, %{secure: false} = state),
    do: {:ok, payload, nil, state}

  defp process_secure(buffer, header, payload, %{context: context, secure: true} = state) do
    {payload, suffix} =
      PacketParser.extract_suffix(payload, context.mki_indicator, context.auth_tag_size)

    {auth_portion, _suffix} =
      PacketParser.extract_suffix(
        buffer.payload,
        context.mki_indicator,
        context.auth_tag_size
      )

    with {:ok, payload, updates} <-
           Secure.process_payload(payload, auth_portion, context, header, suffix) do
      context = Secure.update_context(context, updates)
      {:ok, payload, suffix, %{state | context: context}}
    end
  end

  @spec build_commands(Packet.t(), Buffer.t(), State.t()) :: {[Action.t()], State.t()}
  defp build_commands(packet, buffer, state)

  defp build_commands(%Packet{} = packet, buffer, %State{raw_payload_type: nil} = state) do
    %Packet{header: %Header{payload_type: pt}} = packet
    {commands, state} = build_commands(packet, buffer, %State{state | raw_payload_type: pt})
    caps = build_caps(packet)
    {[caps | commands], state}
  end

  defp build_commands(packet, buffer, %State{raw_payload_type: _} = state) do
    buffer = build_buffer(buffer, packet)
    commands = [buffer: {:output, buffer}]
    {commands, state}
  end

  @spec build_caps(Packet.t()) :: Action.caps_t()
  defp build_caps(%Packet{header: header}) do
    %Header{
      payload_type: payload_type
    } = header

    caps = %Caps{
      raw_payload_type: payload_type,
      payload_type: PayloadTypeDecoder.decode_payload_type(payload_type)
    }

    {:caps, {:output, caps}}
  end

  @spec build_buffer(Buffer.t(), Packet.t()) :: Buffer.t()
  defp build_buffer(
         %Buffer{metadata: metadata} = original_buffer,
         %Packet{payload: payload} = packet
       ) do
    updated_metadata = build_metadata(packet, metadata)
    %Buffer{original_buffer | payload: payload, metadata: updated_metadata}
  end

  @spec build_metadata(Packet.t(), map()) :: map()
  defp build_metadata(%Packet{header: %Header{} = header}, metadata) do
    extracted = Map.take(header, @metadata_fields)
    Map.put(metadata, :rtp, extracted)
  end
end
