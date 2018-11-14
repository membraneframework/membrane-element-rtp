defmodule Membrane.Element.RTP.FilterTest do
  use ExUnit.Case
  alias Membrane.Element.RTP.{SamplePacket, Filter}
  alias Membrane.Buffer

  test "handles correct RTP frame properly" do
    assert Filter.handle_process(
             :input,
             %Buffer{payload: SamplePacket.sample_packet()},
             nil,
             nil
           ) ==
             {{:ok,
               [
                 buffer: {:output, SamplePacket.sample_buffer()},
                 redemand: :output
               ]}, nil}
  end
end
