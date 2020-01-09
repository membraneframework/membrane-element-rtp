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
    {:ok, cnode} = CNode.start_link(:handshaker)
    addr_as_string = opts.local_addr |> Tuple.to_list() |> Enum.join(".")

    state = %{
      cert_file: opts.cert_file,
      pkey_file: opts.pkey_file,
      local_port: opts.local_port,
      local_addr: addr_as_string,
      cnode: cnode
    }

    {:ok, state}
  end

  @impl true
  def handle_stopped_to_prepared(_ctx, state) do
    msg = {
      {:cert_file, state.cert_file},
      {:pkey_file, state.pkey_file},
      {:local_addr, state.local_addr},
      {:local_port, state.local_port}
    }

    {cnode, :ok} = state.cnode |> CNode.call(msg)

    {:ok, state}
  end

  @impl true
  @spec handle_other({CNode.t(), any}, any, any) :: any
  def handle_other({cnode, packet}, _ctx, state) do
    buff_cntn = %Buffer{payload: packet}
    action = [buffer: {:output, buff_cntn}]
    {{:ok, action}, state}
  end
end
