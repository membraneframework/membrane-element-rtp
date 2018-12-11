defmodule Membrane.Element.RTP.PipelineTest do
  use ExUnit.Case

  alias Membrane.Buffer
  alias Membrane.Element.RTP.{Parser, SamplePacket}
  alias Membrane.Pipeline
  alias Membrane.Testing

  test "Pipeline decodes set of RTP packets" do
    test_data_base = 1..100
    test_data = SamplePacket.fake_packet_list(test_data_base)

    {:ok, pipeline} =
      Pipeline.start_link(Testing.Pipeline, %Testing.Pipeline.Options{
        elements: [
          source: %Testing.DataSource{data: test_data},
          parser: Parser,
          sink: %Testing.Sink{target: self()}
        ],
        test_process: self()
      })

    Pipeline.play(pipeline)

    result =
      Enum.map(1..100, fn _ ->
        assert_receive %Buffer{}, 1000
      end)

    assert length(result) == Enum.count(test_data_base)
  end
end
