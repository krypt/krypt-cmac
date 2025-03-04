module Krypt
  class Cmac
    # Implements AES-CMAC-PRF-128 as defined in RFC 4615. Variable length keys are supported,
    # but if the key is not 128 bits long, it is derived using the AES-CMAC algorithm to enforce
    # a 128 bit key and a CMAC computed with AES-128. All methods of Krypt::Cmac are available.
    #
    # @example
    #   key = ["0102030405"].pack("H*")
    #   prf = Krypt::Cmac::CmacPrf128.new(key)
    #   tag = prf.digest("data")
    #
    # @see Krypt::Cmac
    #
    # References:
    # - AES-CMAC-PRF-128 RFC: https://tools.ietf.org/html/rfc4615
    class CmacPrf128
      def initialize(key)
        @key = derive_key(key)
        @cmac = Krypt::Cmac.new(@key)
      end

      # Delegates to the underlying Krypt::Cmac instance.
      def method_missing(method, *args, &block)
        if @cmac.respond_to?(method)
          @cmac.send(method, *args, &block)
        else
          super
        end
      end

      # Delegates to the underlying Krypt::Cmac instance.
      def respond_to_missing?(method, include_private = false)
        @cmac.respond_to?(method) || super
      end

      private

      def derive_key(key)
        # If the key is already 128 bits, return it as is
        return key if key.bytesize == 16

        # Otherwise, derive a 128-bit key using the AES-CMAC algorithm
        cmac = Krypt::Cmac.new(Krypt::Cmac::BLOCK_OF_ZEROS)
        cmac.digest(key)
      end
    end
  end
end
