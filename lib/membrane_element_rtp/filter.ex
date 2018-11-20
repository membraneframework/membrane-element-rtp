defmodule Membrane.Element.RTP.Filter do
  @moduledoc """
  Parses RTP packets
  See `options/0` for available options
  """
  use Membrane.Element.Base.Filter

  alias Membrane.Element.RTP.Parser
  alias Membrane.Element.RTP.Packet
  alias Membrane.Caps.RTP, as: Caps
  alias Membrane.Buffer
  alias Membrane.Caps.Matcher

  @supported_caps {Caps, payload_type: Matcher.range(0, 127)}

  def_output_pads output: [
                    caps: @supported_caps
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

  # TODO: Send error when invalid payload_type

  @impl true
  def handle_init(%__MODULE__{} = options) do
    {:ok, Map.from_struct(options)}
  end

  @impl true
  def handle_stopped_to_prepared(_ctx, %{payload_type: payload_type} = state) do
    {{:ok, caps: {:output, %Caps{payload_type: payload_type}}}, state}
  end

  @impl true
  def handle_process(
        :input,
        %Buffer{payload: buffer_payload, metadata: meta} = buffer,
        _ctx,
        state
      ) do
    case Parser.parse_frame(buffer_payload) do
      {:ok, %Packet{header: header, payload: payload}} ->
        buffer = %Buffer{
          buffer
          | payload: payload,
            metadata: Map.put(meta, :rtp_header, header)
        }

        {{:ok, buffer: {:output, buffer}, redemand: :output}, state}

      {:error, reason} ->
        {{:error, reason}, state}
    end
  end

  @impl true
  def handle_demand(:output, size, _, _ctx, state) do
    {{:ok, demand: {:input, size}}, state}
  end
end
