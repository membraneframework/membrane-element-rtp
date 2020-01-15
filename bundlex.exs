defmodule Membrane.Element.RTP.BundlexProject do
  use Bundlex.Project

  def project() do
    [cnodes: cnodes()]
  end

  defp cnodes() do
    [
      handshaker: [
        sources: ["handshaker.c", "cnodeserver.c"],
        includes: includes(Bundlex.platform()),
        lib_dirs: includes(Bundlex.platform()),
        libs: ["crypto", "ssl"],
        deps: [membrane_libdtlssrtp_wrapper: :libdtlssrtp]
      ]
    ]
  end

  defp libs_dirs(:macosx) do
    ["/usr/local/opt/openssl/lib"]
  end

  defp lib_dirs(_os_type) do
    []
  end

  defp includes(:macosx) do
    ["/usr/local/opt/openssl/include"]
  end

  defp includes(_os_type) do
    []
  end
end
