defmodule Membrane.Element.RTP.SRTP.UnifexSource do
  @moduledoc """
  Element that starts CNode, which performs DTLS-SRTP handshakes with clients and forwards arriving packets and keys via output pad.
  """

  require Unifex.UnifexCNode

  alias Unifex.UnifexCNode
  alias Membrane.Element.RTP.SRTP.KeySet
  alias Membrane.Buffer

  use Membrane.Source

  def_options cert_file: [
                type: :string,
                description: "Path to file with certificate"
              ],
              pkey_file: [
                type: :string,
                description: "Path to file with key"
              ],
              local_addr: [
                type: :ip_address,
                spec: :inet.ip_address(),
                description: """
                An IP Address on which SRTP server will listen
                """
              ],
              local_port: [
                type: :integer,
                spec: pos_integer,
                description: """
                A UDP port number used when opening SRTP server
                """
              ]

  def_output_pad :output,
    caps: :any,
    mode: :push

  @impl true
  def handle_init(%__MODULE__{} = opts) do
    state = %{
      cert_file: opts.cert_file,
      pkey_file: opts.pkey_file,
      local_port: opts.local_port,
      local_addr: opts.local_addr,
      cnode: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_stopped_to_prepared(_ctx, state) do
    {:ok, cnode} = UnifexCNode.start_link(:unifex_handshaker)

    server_config = [
      state.cert_file,
      state.pkey_file,
      state.local_addr |> Tuple.to_list() |> Enum.join("."),
      state.local_port
    ]

    cnode |> UnifexCNode.cast(:start_server, server_config)

    receive do
      {:server_running} -> :ok
    after
      5000 -> raise "DTLS-SRTP server not running"
    end

    {:ok, %{state | cnode: cnode}}
  end

  @impl true
  def handle_prepared_to_stopped(_ctx, state) do
    UnifexCNode.stop(state.cnode)
    {:ok, state}
  end

  @impl true
  def handle_other(_msg, %{playback_state: :stopped} = _ctx, state) do
    {:ok, state}
  end

  @impl true
  def handle_other({:key_set, localkey, remotekey, localsalt, remotesalt}, _ctx, state) do
    key_set = %KeySet{
      localkey: localkey,
      remotekey: remotekey,
      localsalt: localsalt,
      remotesalt: remotesalt
    }

    event_action = {:event, {:output, key_set}}
    {{:ok, event_action}, state}
  end

  @impl true
  def handle_other({:packet, content}, _ctx, state) do
    buff_cntn = %Buffer{payload: content}
    action = [buffer: {:output, buff_cntn}]
    {{:ok, action}, state}
  end
end
