require_relative "../spec_helper"

describe SSHData::PublicKey::MLDSA44ED25519 do
  let(:openssh_key) { SSHData::PublicKey.parse_openssh(fixture("mldsa44_ed25519.pub")) }
  let(:signature) { SSHData::Signature.parse_pem(fixture("signatures/message.mldsa44-ed25519.sig")) }
  let(:message) { fixture("signatures/message") }
  let(:pk) { "a" * described_class::COMPOSITE_PUBLIC_KEY_SIZE }

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_MLDSA44ED25519,
      pk: pk
    )
  end

  it "is equal to keys with the same params" do
    expect(subject).to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_MLDSA44ED25519,
      pk: pk
    ))
  end

  it "isnt equal to keys with different params" do
    expect(subject).not_to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_MLDSA44ED25519,
      pk: "b" * described_class::COMPOSITE_PUBLIC_KEY_SIZE
    ))
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_MLDSA44ED25519)
  end

  it "has parameters" do
    expect(subject.pk).to eq(pk)
  end

  it "rejects bad key lengths" do
    expect {
      described_class.new(
        algo: SSHData::PublicKey::ALGO_MLDSA44ED25519,
        pk: "a" * (described_class::COMPOSITE_PUBLIC_KEY_SIZE - 1)
      )
    }.to raise_error(SSHData::DecodeError, "bad pk")
  end

  it "can parse openssh-generated keys" do
    expect(openssh_key).to be_a(described_class)
    expect(openssh_key.pk.bytesize).to eq(described_class::COMPOSITE_PUBLIC_KEY_SIZE)
  end

  it "can be rencoded" do
    expect(openssh_key.rfc4253).to eq(fixture("mldsa44_ed25519.pub", binary: true))
  end

  it "can parse openssh-generated signatures" do
    sig_algo, raw_sig, = SSHData::Encoding.decode_signature(signature.signature)

    expect(signature.public_key).to be_a(described_class)
    expect(sig_algo).to eq(SSHData::PublicKey::ALGO_MLDSA44ED25519)
    expect(raw_sig.bytesize).to eq(described_class::COMPOSITE_SIGNATURE_SIZE)
  end

  it "can verify openssh-generated signatures" do
    skip "ML-DSA-44 is not supported by this OpenSSL" unless described_class.enabled?

    expect(signature.verify(message)).to be(true)
    expect(signature.verify(message + "bad")).to be(false)
  end
end
