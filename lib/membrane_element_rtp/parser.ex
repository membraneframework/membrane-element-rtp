defmodule Membrane.Element.RTP.Parser do
  @moduledoc """
  Parses RTP packets
  See `options/0` for available options
  """
  use Membrane.Element.Base.Filter

  alias Membrane.Buffer
  alias Membrane.Caps.RTP, as: Caps
  alias Membrane.Element.Action
  alias Membrane.Element.RTP.{PacketParser, Packet, Header, PayloadTypeDecoder}

  @metadata_fields [:timestamp, :sequence_number]

  def_output_pads output: [
                    caps: Caps
                  ]

  def_input_pads input: [
                   caps: :any,
                   demand_unit: :buffers
                 ]

  def_options payload_type: [
                type: :integer,
                description: """
                Expected payload type.
                """
              ]

  # TODO: Send caps when first buffer arrives

  @impl true
  def handle_init(%__MODULE__{} = options) do
    {:ok, %{}}
  end

  @impl true
  def handle_process(:input, %Buffer{payload: buffer_payload} = buffer, _ctx, state) do
    with {:ok, %Packet{} = packet} <- PacketParser.parse_frame(buffer_payload),
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

  @spec build_commands(Packet.t(), Buffer.t(), map()) :: {[Action.t()]}
  defp build_commands(packet, buffer, state)

  defp build_commands(packet, buffer, %{base_timestamp: _} = state) do
    buffer = build_buffer(buffer, packet)
    commands = [buffer: {:output, buffer}]
    {commands, state}
  end

  defp build_commands(%Packet{} = packet, buffer, state) do
    %Packet{header: %Header{timestamp: timestamp}} = packet
    {commands, state} = build_commands(packet, buffer, %{state | base_timestamp: timestamp})
    caps = build_caps(packet)
    {[caps | commands], state}
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
