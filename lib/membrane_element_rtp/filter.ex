defmodule Membrane.Element.RTP.Filter do
  use Membrane.Element.Base.Filter

  alias Membrane.Element.RTP.{Frame, Parser}
  alias Membrane.Buffer

  def_known_source_pads(source: {:always, :pull, :any})

  def_known_sink_pads(sink: {:always, {:pull, demand_in: :buffers}, :any})

  def handle_process(:sink, buffers, context, state) do
    buffers =
      Enum.map(buffers, fn %Buffer{payload: buffer_payload} = buffer ->
        %Frame{payload: payload} = result = Parser.parse_frame(buffer_payload)
        IO.inspect(result)
        IO.inspect(byte_size(result.payload))
        %Buffer{buffer | payload: payload}
      end)

    {{:ok, buffer: {:source, buffers}}, state}
  end

  @impl true
  def handle_demand(:source, size, :buffers, _, state) do
    {{:ok, demand: {:sink, size}}, state}
  end

  def handle_demand(:source, _size, :bytes, _, state) do
    {{:ok, demand: :sink}, state}
  end
end
