defmodule Membrane.Element.RTP.Secure.ParserTest do
  use ExUnit.Case

  alias Membrane.Buffer
  alias Membrane.Element.RTP.{SamplePacket, Secure}
  alias Membrane.Element.RTP.Secure.{Context, MasterKey}

  use Bitwise

  test("parses srtp packets") do
    tp = SamplePacket.sample_srtp_packet()
    assert is_binary(tp)

    key = <<1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
    salt = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>

    mk = %MasterKey{
      key: key,
      salt: salt,
      key_derivation_rate: 0
    }

    context = %Context{from_to_list: [{2100, 2200, 0}], master_keys: %{0 => mk}}
    assert {:ok, result, _updates} = Secure.process_buffer(context, %Buffer{payload: tp})
  end
end

defmodule Membrane.Element.RTP.Secure.SessionKeysTest do
  use ExUnit.Case

  alias Membrane.Element.RTP.Secure.{Context, MasterKey, SessionKeys}

  # Testing with test data from page 53 RFC 3711
  test("derives keys correctly") do
    mk = %MasterKey{
      key: decode("E1F97A0D3E018BE0D64FA32C06DE4139"),
      salt: decode("0EC675AD498AFEEBB6960B3AABE6"),
      key_derivation_rate: 0
    }

    context = %Context{
      encryption_key_size: 16 * 8,
      auth_key_size: 94 * 8,
      salt_size: 14 * 8,
      master_keys: %{0 => mk},
      from_to_list: [{0, 10000, 0}]
    }

    index = 0
    {_, session_keys} = SessionKeys.get_or_derive_session_keys(context, 0, index)

    correct = %{
      srtp_encr: decode("C61E7A93744F39EE10734AFE3FF7A087"),
      srtp_salt: decode("30CBBC08863D8C85D49DB34A9AE1"),
      srtp_auth:
        decode(
          "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA48F0A0ACF3C34E2359E6CDBCEE049646C43D9327AD175578EF72270986371C10C9A369AC2F94A8C5FBCDDDC256D6E919A48B610EF17C2041E474035766B68642C59BBFC2F34DB60DBDFB2"
        )
    }

    assert correct == session_keys
  end

  defp decode(p) do
    p
    |> Base.decode16()
    |> case do
      {:ok, b} -> b
    end
  end
end
