module Krypt
  class Cmac
    # Implements AES-CMAC-96 as defined in RFC 4494. Computes a regular
    # 128 bit tag and truncates it at 96 bit. All methods of Krypt::Cmac are available.
    #
    # @example
    #   key = ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*")
    #   message = ["6bc1bee22e409f96e93d7e117393172a"].pack("H*")
    #   prf = Krypt::Cmac::Cmac96.new(key)
    #   tag = prf.digest("data")
    #
    # @see Krypt::Cmac
    #
    # References:
    # - AES-CMAC-96 RFC: https://tools.ietf.org/html/rfc4494
    class Cmac96 < Cmac
      def initialize(key)
        super
      end

      # Returns the computed MAC tag as a 96-bit string as described in RFC 4494.
      #
      # @param data [String] The data to update the CMAC computation with before finalizing.
      #   If nil, the CMAC computation is finalized without updating with any data.
      # @return [String] The computed MAC tag as a 96-bit string.
      def digest(data = nil)
        super.byteslice(0, 12)
      end
    end
  end
end
