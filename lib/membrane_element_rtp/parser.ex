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
  alias Membrane.Element.RTP.{Header, Packet, PacketParser, PayloadTypeDecoder}
  alias Membrane.Event.NewContext

  @metadata_fields [:timestamp, :sequence_number, :ssrc, :payload_type]

  def_options context_map: [
                spec: %{Context.id_t() => Context.t()},
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
              context_map: nil

    @type t :: %__MODULE__{
            raw_payload_type: Caps.raw_payload_type() | nil,
            secure: boolean(),
            context_map: nil | %{Context.id_t() => Context.t()}
          }
  end

  @impl true
  def handle_init(opts) do
    {:ok, %State{secure: opts.secure, context_map: opts.context_map}}
  end

  @impl true
  def handle_event(:input, %NewContext{context_id: id, context: ctx}, _event_ctx, state) do
    state = put_in(state, [:context_map, id], ctx)
    {:ok, state}
  end

  @impl true
  def handle_event(:input, event, _ctx, state) do
    {{:ok, event: {:output, event}}, state}
  end

  @impl true
  def handle_process(:input, buffer, _ctx, state) do
    buffer
    |> process_buffer(state)
    |> case do
      {:ok, {packet, state}} ->
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

  @spec process_buffer(Buffer.t(), State.t()) :: {:ok, {Packet.t(), State.t()}} | {:error, atom()}

  defp process_buffer(buffer, %State{secure: false} = state) do
    with {:ok, packet} <- PacketParser.parse_packet(buffer.payload) do
      {:ok, {packet, state}}
    end
  end

  defp process_buffer(buffer, %State{secure: true} = state) do
    {header, rest} = PacketParser.parse_header(buffer.payload)

    with {:ok, context, context_id} <-
           Secure.get_context(state.context_map, header.ssrc, buffer.metadata),
         {payload, suffix} =
           PacketParser.extract_suffix(rest, context.mki_indicator, context.auth_tag_size),
         {auth_portion, _suffix} =
           PacketParser.extract_suffix(
             buffer.payload,
             context.mki_indicator,
             context.auth_tag_size
           ),
         {:ok, payload, updates} <-
           Secure.process_payload(payload, auth_portion, context, header, suffix),
         payload = PacketParser.ignore_padding(payload, header.padding),
         {:ok, context} <- Secure.update_context(context, updates) do
      packet = Map.put(buffer, :payload, payload)
      state = put_in(state, [:context_map, context_id], context)
      {:ok, {packet, state}}
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
