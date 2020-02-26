defmodule Membrane.Element.RTP.BundlexProject do
  use Bundlex.Project

  def project() do
    [
      cnodes: cnodes()
    ]
  end

  defp cnodes() do
    dev_cnodes() ++ optional_test_cnodes(Mix.env())
  end

  defp dev_cnodes() do
    [
      unifex_handshaker: [
        sources: ["unifex_handshaker.c", "_generated/unifex_handshaker.c"],
        includes: includes(Bundlex.platform()),
        lib_dirs: lib_dirs(Bundlex.platform()),
        libs: ["crypto", "ssl"],
        deps: [membrane_libdtlssrtp_wrapper: :handshaker_utils, unifex: :cnode_utils]
      ]
      # ,
      # handshaker: [
      #   sources: ["handshaker.c", "cnodeserver.c"],
      #   includes: includes(Bundlex.platform()),
      #   lib_dirs: lib_dirs(Bundlex.platform()),
      #   libs: ["crypto", "ssl"],
      #   deps: [membrane_libdtlssrtp_wrapper: :handshaker_utils]
      # ]
    ]
  end

  defp optional_test_cnodes(:test) do
    [
      test_client: [
        sources: ["test_client.c"],
        includes: includes(Bundlex.platform()),
        lib_dirs: lib_dirs(Bundlex.platform()),
        libs: ["crypto", "ssl"],
        deps: [membrane_libdtlssrtp_wrapper: :dummy_client]
      ]
    ]
  end

  defp optional_test_cnodes(_env) do
    []
  end

  defp lib_dirs(:macosx) do
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
