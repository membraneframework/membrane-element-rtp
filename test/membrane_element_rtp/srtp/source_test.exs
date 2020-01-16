defmodule Membrane.Element.RTP.SRTP.SourceTest do
  use ExUnit.Case

  import Membrane.Testing.Assertions

  require Bundlex.CNode

  alias Membrane.Element.RTP.SRTP.Source
  alias Membrane.Element.RTP.SRTP.KeySet
  alias Membrane.Buffer
  alias Bundlex.CNode

  defp is_action_with_event({{:ok, [buffer: {pad, %Buffer{} = buff_cntn}]}, state}) do
    false
  end

  defp is_action_with_event({{:ok, {:event, {pad, %KeySet{} = key_set}}}, state}) do
    true
  end

  defp is_action_with_event(msg) do
    flunk("Unexpected format of received message!\nmessage:\n" <> inspect(msg, pretty: true))
  end

  defp receive_and_handle(state) do
    receive do
      msg ->
        empty_ctx = %{}
        Source.handle_other(msg, empty_ctx, state)
    after
      5000 ->
        flunk("Timeout exceed!\n")
    end
  end

  defp receive_and_handle_loop(state, range, accumulator \\ []) do
    if range <= 0 do
      accumulator
    else
      accumulator = [receive_and_handle(state) | accumulator]
      receive_and_handle_loop(state, range - 1, accumulator)
    end
  end

  defp counting_loop(answers, counter \\ %{packets: 0, keys: 0}) do
    with [head | tail] <- answers do
      counter =
        if is_action_with_event(head) do
          %{counter | keys: counter.keys + 1}
        else
          %{counter | packets: counter.packets + 1}
        end

      counting_loop(tail, counter)
    else
      empty_list -> counter
    end
  end

  test "Source starts CNode, performs handshake and forwards given messages" do
    client_cmd = "_build/dev/lib/membrane_element_rtp/priv/bundlex/test_client"
    path_prefix = "test/fixtures/dtls_srtp/"
    cert_file = path_prefix <> "MyCertificate.crt"
    pkey_file = path_prefix <> "MyKey.key"
    local_addr = {127, 0, 0, 1}
    local_addr_as_string = local_addr |> Tuple.to_list() |> Enum.join(".")
    server_port = 6969
    client_port = 6970
    empty_ctx = %{}

    source_opts = %Source{
      cert_file: cert_file,
      pkey_file: pkey_file,
      local_addr: local_addr,
      local_port: server_port
    }

    {:ok, source_state} = Source.handle_init(source_opts)
    {:ok, source_state} = Source.handle_stopped_to_prepared(empty_ctx, source_state)

    client_argv = [
      "-k",
      pkey_file,
      "-c",
      cert_file,
      "-b",
      local_addr_as_string,
      "-p",
      client_port,
      local_addr_as_string,
      server_port
    ]

    command = ([client_cmd] ++ client_argv ++ ["&"]) |> Enum.join(" ") |> to_charlist
    :os.cmd(command)

    counter = source_state |> receive_and_handle_loop(11) |> counting_loop()
    assert counter == %{packets: 10, keys: 1}
  end
end
