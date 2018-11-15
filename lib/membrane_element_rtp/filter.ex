defmodule Membrane.Element.RTP.Filter do
  @moduledoc """
  Parses RTP packets
  See `options/0` for available options
  """
  use Membrane.Element.Base.Filter

  alias Membrane.Element.RTP.{Packet, Parser}
  alias Membrane.Buffer

  def_output_pads(
    output: [
      caps: :any
    ]
  )

  def_input_pads(
    input: [
      caps: :any,
      demand_unit: :buffers
    ]
  )

  # Private API
  @impl true
  def handle_init(options) do
    {:ok,
     %{
       last_packet: 0
     }}
  end

  @impl true
  def handle_process(
        :input,
        %Buffer{payload: buffer_payload, metadata: meta} = buffer,
        _ctx,
        state
      ) do
    case Parser.parse_frame(buffer_payload) do
      {:ok, packet} ->
        %Packet{payload: payload, header: header} = packet

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
