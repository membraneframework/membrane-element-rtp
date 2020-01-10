defmodule Membrane.Element.RTP.SRTP.Source do
  require Bundlex.CNode

  alias Membrane.Buffer
  alias Bundlex.CNode

  use Membrane.Source
  # use Bunch

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
    {:ok, cnode} = CNode.start_link(:handshaker)

    msg = {
      state.cert_file,
      state.pkey_file,
      state.local_addr |> Tuple.to_list() |> Enum.join("."),
      state.local_port
    }

    {node, :ok} = cnode |> CNode.call(msg)

    {:ok, %{state | cnode: cnode}}
  end

  @impl true
  @spec handle_other({CNode.t(), any}, any, any) :: any
  def handle_other({cnode, packet}, _ctx, state) do
    buff_cntn = %Buffer{payload: packet}
    action = [buffer: {:output, buff_cntn}]
    {{:ok, action}, state}
  end
end
