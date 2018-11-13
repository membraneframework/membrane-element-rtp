defmodule Membrane.Element.RTP.Filter do
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

  def handle_process(
        :input,
        %Buffer{payload: buffer_payload, metadata: meta} = buffer,
        context,
        state
      ) do
    %Packet{payload: payload, header: header} = result = Parser.parse_frame(buffer_payload)
    buffer = %Buffer{buffer | payload: payload, metadata: Map.put(meta, :rtp_header, header)}

    {{:ok, buffer: {:output, buffer}}, state}
  end

  @impl true
  def handle_demand(:output, size, _, _ctx, state) do
    {{:ok, demand: {:input, size}}, state}
  end
end
