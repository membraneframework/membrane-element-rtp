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
        lib_dirs: lib_dirs(Bundlex.platform()),
        libs: ["crypto", "ssl"],
        deps: [membrane_libdtlssrtp_wrapper: :handshaker_utils]
      ]
    ] ++ cnodes_if_env_test(Mix.env())
  end

  defp cnodes_if_env_test(:test) do
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

  defp cnodes_if_env_test(_env) do
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
