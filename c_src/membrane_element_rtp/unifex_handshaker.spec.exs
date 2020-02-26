module UnifexHandshaker

cnode_mode true

spec start_server(cert_file :: string, pkey_file :: string, local_addr :: string, local_port :: int) :: void

sends {:key_set :: label, localkey :: string, remotekey :: string, localsalt :: string, remotesalt :: string}
sends {:packet :: label, content :: string}
sends {:server_running :: label}
sends {:error :: label, reason :: string}