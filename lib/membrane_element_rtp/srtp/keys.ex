defmodule Membrane.Element.RTP.SRTP.KeySet do
  @derive Membrane.EventProtocol

  @enforce_keys [:localkey, :remotekey, :localsalt, :remotesalt]
  defstruct @enforce_keys
end
