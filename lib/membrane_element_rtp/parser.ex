defmodule Membrane.Element.RTP.Parser do
  @moduledoc """
  Parses RTP packets.
  See `options/0` for available options
  """

  use Membrane.Filter

  alias Membrane.Buffer
  alias Membrane.Caps.RTP, as: Caps
  alias Membrane.Element.Action
  alias Membrane.Element.RTP.Secure.Context
  alias Membrane.Element.RTP.{Header, Packet, PacketParser, PayloadTypeDecoder, Secure}

  @metadata_fields [:timestamp, :sequence_number, :ssrc, :payload_type]

  def_options context_map: [
                spec: %{Context.id() => Context.t()},
                default: %{}
              ],
              secure: [
                spec: boolean(),
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
            context_map: nil | %{Context.id() => Context.t()}
          }
  end

  @impl true
  def handle_init(opts) do
    {:ok, %State{secure: opts.secure, context_map: opts.context_map}}
  end

  @impl
  def handle_event(_, %NewContext{context_id: id, context: ctx} = event, _, state) do
    state = put_in(state, [:context_map, id], ctx)
    {:ok, state}
  end

  @impl true
  def handle_process(:input, %Buffer{payload: buffer_payload} = buffer, _ctx, state) do
    with {:ok, {packet, state}} <- process_payload(buffer_payload, state),
         {commands, state} <- build_commands(packet, buffer, state) do
      {{:ok, commands}, state}
    else
      {:error, reason} ->
        {{:error, reason}, state}
    end
  end

  @impl true
  def handle_demand(:output, size, _unit, _ctx, state) do
    {{:ok, demand: {:input, size}}, state}
  end

  defp process_payload(payload, %State{secure: false} = state) do
    with {:ok, packet} <- PacketParser.parse_packet(payload) do
      {:ok, {packet, state}}
    end
  end

  defp process_payload(buffer, %State{secure: true} = state) do
    with {:ok, context, context_id} <- Secure.get_context(state.context_map, buffer.payload),
         {:ok, packet, updates} <- Secure.process_buffer(context, buffer),
         {:ok, context} <- Secure.update_context(context, updates) do
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
