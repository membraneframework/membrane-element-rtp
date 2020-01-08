defmodule Membrane.Element.RTP.BundlexProject do
    use Bundlex.Project

    def project() do
        [
            cnodes: cnodes(),
        ]
    end

    defp cnodes() do
        [
            handshaker: [
                sources: 
                [
                    "handshaker.c", 
                    "cnodeserver.c", 
                    "../../../../Documents/libdtlssrtp/dtls_srtp.c", 
                    "../../../../Documents/libdtlssrtp/dsink_udp.c" 
                ],
                includes: ["/usr/local/opt/openssl/include"],
                lib_dirs: ["/usr/local/opt/openssl/lib"],
                libs: ["crypto", "ssl"],
            ]
        ]
    end

end