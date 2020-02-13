defmodule Membrane.Element.RTP.PipelineTest do
  use ExUnit.Case

  import Membrane.Testing.Assertions

  alias Membrane.Buffer
  alias Membrane.Element.RTP.{Parser, SamplePacket}
  alias Membrane.Element.RTP.Parser.Secure.{Context, MasterKey}
  alias Membrane.Testing.{Source, Pipeline, Sink}

  @buffer_receive_timeout 1000

  test "Pipeline decodes set of RTP packets" do
    test_data_base = 1..100
    test_data = SamplePacket.fake_packet_list(test_data_base)

    {:ok, pipeline} =
      Pipeline.start_link(%Pipeline.Options{
        elements: [
          source: %Source{output: test_data},
          parser: %Parser{secure: false},
          sink: %Sink{}
        ]
      })

    Pipeline.play(pipeline)

    Enum.each(test_data_base, fn _ ->
      assert_sink_buffer(pipeline, :sink, %Buffer{}, @buffer_receive_timeout)
    end)
  end

  test "Pipeline decodes a set of SRTP packets" do
    test_data = SamplePacket.srtp_packet_list()

    key = <<1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
    salt = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>

    mk = %MasterKey{key: key, salt: salt}

    context = %Context{
      master_keys: %{1 => mk},
      from_to_list: [{0, 1_000_000, 1}]
    }

    {:ok, pipeline} =
      Pipeline.start_link(%Pipeline.Options{
        elements: [
          source: %Source{output: test_data},
          parser: %Parser{secure: true, context: context},
          sink: %Sink{}
        ]
      })

    Pipeline.play(pipeline)

    Enum.each(test_data, fn _ ->
      assert_sink_buffer(pipeline, :sink, %Buffer{}, @buffer_receive_timeout)
    end)
  end
end
