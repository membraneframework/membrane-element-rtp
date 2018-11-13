defmodule Membrane.Element.RTP.Filter do
  @moduledoc """
  Parses RTP packets
  See `options/0` for available options
  """
  use Membrane.Element.Base.Filter

  alias Membrane.Element.RTP.{Packet, Parser}
  alias Membrane.Buffer

  @packet_size_threshold 1600

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

  def handle_process(
        :input,
        %Buffer{payload: buffer_payload, metadata: meta} = buffer,
        _ctx,
        state
      ) do
    with {:ok, packet} <- Parser.parse_frame(buffer_payload),
         %Packet{payload: payload, header: header} <- packet when byte_size(payload) > 0,
         buffer <- %Buffer{
           buffer
           | payload: payload,
             metadata: Map.put(meta, :rtp_header, header)
         } do
      {{:ok, buffer: {:output, buffer}, redemand: :output}, state}
    end
  end

  @impl true
  def handle_demand(:output, size, _, _ctx, state) do
    {{:ok, demand: {:input, size}}, state}
  end
end
