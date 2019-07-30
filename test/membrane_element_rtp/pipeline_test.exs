defmodule Membrane.Element.RTP.PipelineTest do
  use ExUnit.Case

  alias Membrane.Buffer
  alias Membrane.Element.RTP.{Parser, SamplePacket}
  alias Membrane.Pipeline
  alias Membrane.Testing

  import Testing.Assertions

  @buffer_receive_timeout 1000

  test "Pipeline decodes set of RTP packets" do
    test_data_base = 1..100
    test_data = SamplePacket.fake_packet_list(test_data_base)

    {:ok, pipeline} =
      Testing.Pipeline.start_link(%Testing.Pipeline.Options{
        elements: [
          source: %Testing.Source{output: test_data},
          parser: Parser,
          sink: %Testing.Sink{}
        ]
      })

    Pipeline.play(pipeline)

    Enum.each(test_data, fn packet ->
      assert_sink_buffer(pipeline, :sink, %Buffer{payload: payload}, @buffer_receive_timeout)
      assert packet =~ packet
    end)
  end
end
