module SSHData
  module PublicKey
    class MLDSA44ED25519 < Base
      attr_reader :pk

      MLDSA_PUBLIC_KEY_SIZE = 1312
      ED25519_PUBLIC_KEY_SIZE = 32
      COMPOSITE_PUBLIC_KEY_SIZE = MLDSA_PUBLIC_KEY_SIZE + ED25519_PUBLIC_KEY_SIZE

      MLDSA_SIGNATURE_SIZE = 2420
      ED25519_SIGNATURE_SIZE = 64
      COMPOSITE_SIGNATURE_SIZE = MLDSA_SIGNATURE_SIZE + ED25519_SIGNATURE_SIZE

      COMPOSITE_PREFIX = "CompositeAlgorithmSignatures2025"
      COMPOSITE_LABEL = "COMPSIG-MLDSA44-Ed25519-SHA512"
      MIN_OPENSSL_VERSION = 0x30500000

      def self.enabled?
        OpenSSL::OPENSSL_VERSION_NUMBER >= MIN_OPENSSL_VERSION
      end

      def self.openssl_required!
        unless enabled?
          raise AlgorithmError, "#{ALGO_MLDSA44ED25519} requires OpenSSL 3.5 or later"
        end
      end

      def initialize(algo:, pk:)
        unless algo == ALGO_MLDSA44ED25519
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        if pk.bytesize != COMPOSITE_PUBLIC_KEY_SIZE
          raise DecodeError, "bad pk"
        end

        @pk = pk
        super(algo: algo)
      end

      # Verify an SSH signature.
      #
      # signed_data - The String message that the signature was calculated over.
      # signature   - The binary String signature with SSH encoding.
      #
      # Returns boolean.
      def verify(signed_data, signature)
        self.class.openssl_required!

        sig_algo, raw_sig, _ = Encoding.decode_signature(signature)
        if sig_algo != ALGO_MLDSA44ED25519
          raise DecodeError, "bad signature algorithm: #{sig_algo.inspect}"
        end

        if raw_sig.bytesize != COMPOSITE_SIGNATURE_SIZE
          raise DecodeError, "bad signature length"
        end

        m_prime = message_representative(signed_data)
        mldsa_sig = raw_sig.byteslice(0, MLDSA_SIGNATURE_SIZE)
        ed25519_sig = raw_sig.byteslice(MLDSA_SIGNATURE_SIZE, ED25519_SIGNATURE_SIZE)

        # The composite signatures draft explicitly permits verification to fail early, so it's okay to short-circuit here.
        mldsa_key.verify(nil, mldsa_sig, m_prime, "context-string" => COMPOSITE_LABEL) &&
          ed25519_key.verify(nil, ed25519_sig, m_prime)
      end

      # RFC4253 binary encoding of the public key.
      #
      # Returns a binary String.
      def rfc4253
        Encoding.encode_fields(
          [:string, algo],
          [:string, pk],
        )
      end

      # Is this public key equal to another public key?
      #
      # other - Another SSHData::PublicKey::Base instance to compare with.
      #
      # Returns boolean.
      def ==(other)
        super && other.pk == pk
      end

      private

      def mldsa_pk
        pk.byteslice(0, MLDSA_PUBLIC_KEY_SIZE)
      end

      def ed25519_pk
        pk.byteslice(MLDSA_PUBLIC_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE)
      end

      def mldsa_key
        # Use a SubjectPublicKeyInfo for the ML-DSA key for compatibility with ruby/openssl 3.3.
        @mldsa_key ||= OpenSSL::PKey.read(mldsa_asn1.to_der)
      rescue OpenSSL::PKey::PKeyError
        raise DecodeError, "bad key data"
      end

      def ed25519_key
        @ed25519_key ||= OpenSSL::PKey.new_raw_public_key("ED25519", ed25519_pk)
      rescue OpenSSL::PKey::PKeyError
        raise DecodeError, "bad key data"
      end

      def mldsa_asn1
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new("id-ml-dsa-44"),
          ]),
          OpenSSL::ASN1::BitString.new(mldsa_pk),
        ])
      end

      def message_representative(signed_data, context: "")
        if context.bytesize > 255
          raise DecodeError, "signature context too long"
        end

        COMPOSITE_PREFIX +
          COMPOSITE_LABEL +
          [context.bytesize].pack("C") +
          context +
          OpenSSL::Digest::SHA512.digest(signed_data)
      end
    end
  end
end
