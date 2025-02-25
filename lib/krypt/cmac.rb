require "openssl"
require_relative "cmac/version"
require_relative "cmac/errors"
require_relative "cmac/cmac_96"
require_relative "cmac/cmac_prf_128"

module Krypt
  # Based on the CMAC algorithm described in RFC 4493 and NIST SP 800-38B.
  # Calculates a message authentication code (MAC) for a message using AES as the block cipher.
  # The underlying AES key size can be 128, 192, or 256 bits, this governs the
  # version of AES being used to compute the MAC. The MAC size is always 128 bits.
  #
  # If a 96-bit MAC is required (as in RFC 4494), {#cmac_96} can be used. If other
  # reduced versions are required, the MAC tag can be truncated manually after calling
  # {#digest}.
  #
  # If variable length keys such as in AES-CMAC-PRF-128 (RFC 4615) must be supported,
  # or if the MAC shall be computed with AES-128 - regardless of the key length,
  # {Krypt::Cmac::Prf128} can be used. This class derives a 128-bit key from the
  # given key using the AES-CMAC algorithm.
  #
  # The CMAC computation can be updated with data in multiple calls to {#update}
  # or by using the << operator. The MAC tag is finalized by calling {#digest}.
  # The computation can be updated with data before finalizing by passing the
  # data as an argument to {#digest}, allowing for one-shot tag computation.
  #
  # @example
  #   key = ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*")
  #   message = ["6bc1bee22e409f96e93d7e117393172a"].pack("H*")
  #   message2 = ["ae2d8a57"].pack("H*")
  #
  #   # One-shot computation
  #   cmac = Krypt::Cmac.new(key)
  #   tag = cmac.digest(message)
  #
  #   # Streaming computation
  #   cmac = Krypt::Cmac.new(key)
  #   cmac.update(message) # Or: cmac << message
  #   cmac.update(message2)
  #   tag = cmac.digest
  #
  #   # Streaming computation with chaining
  #   tag = Krypt::Cmac.new(key).update(message).update(message2).digest
  #
  # @see Krypt::Cmac::Cmac96
  # @see Krypt::Cmac::Prf128
  #
  # References:
  # - NIST SP 800-38B: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
  # - CMAC RFC: https://tools.ietf.org/html/rfc4493
  # - AES-CMAC-96 RFC: https://tools.ietf.org/html/rfc4494
  # - AES-CMAC-PRF-128 RFC: https://tools.ietf.org/html/rfc4615
  class Cmac
    # The constant string for subkey generation for a cipher with block size 128.
    # Note that this is the same for different key lengths, as AES block size is always 128 bits.
    RB = 0x87
    # AES block size in bytes, which is always 128 (i.e. 16 bytes) regardless of key length.
    AES_BLOCK_SIZE = 16
    # A block of zeros, used for padding and initialization vectors.
    BLOCK_OF_ZEROS = "\0".b * AES_BLOCK_SIZE

    attr_reader :key, :k1, :k2, :l, :mac_tag

    # Creates a new CMAC instance with the given key. The key length determines
    # the version of AES to use for the CMAC computation.
    #
    # @param key [String] The key to use for the CMAC computation.
    #   The key must be 128, 192, or 256 bits long, selecting the AES version to use.
    # @raise [ArgumentError] If the key length is not 128, 192, or 256 bits.
    def initialize(key)
      unless [16, 24, 32].include?(key.bytesize)
        raise ArgumentError, "Key must be 128, 192, or 256 bits long"
      end
      @key = key.b
      @k1, @k2, @l = generate_subkeys(@key)
      @buffer = "".b
      @aes_cbc = cipher_for_key(@key, :CBC)
      @aes_cbc.iv = BLOCK_OF_ZEROS
    end

    # Updates the CMAC computation with the given data. The data can be any
    # string, and the CMAC computation is updated with the data. The data can
    # be given in multiple calls to update, and the CMAC computation is
    # updated with each call.
    #
    # @param data [String] The data to update the CMAC computation with.
    # @return [self] The CMAC instance itself, to allow chaining.
    # @raise [InvalidStateError] If the CMAC has already been finalized.
    def update(data)
      return self if data.nil? || data.empty?
      raise InvalidStateError.new("CMAC has already been finalized") if @mac_tag

      @buffer << data
      # Return early if the buffer does not contain enough data to form a block
      return self if @buffer.bytesize <= AES_BLOCK_SIZE

      # Ensure that we do not process the final block yet. The final block is
      # processed in the digest method. This is to ensure that the final block
      # is padded correctly. For now, just process the remaining full blocks.
      remainder = @buffer.bytesize % AES_BLOCK_SIZE
      remainder = AES_BLOCK_SIZE if remainder == 0
      update_full_blocks(@buffer.slice!(0...-remainder))

      self # Return self to allow chaining
    end
    # Allow the << operator to be used as an alias for update.
    # This allows the CMAC computation to be updated with the << operator.
    # (@see #update)
    alias_method :<<, :update

    # Finalizes the CMAC computation and returns the computed MAC tag. If data
    # is given, the CMAC computation is updated with the data before finalizing.
    # The CMAC computation is finalized after calling this method, and no further
    # updates are allowed.
    #
    # @param data [String] The data to update the CMAC computation with before finalizing.
    #   If nil, the CMAC computation is finalized without updating with any data.
    # @return [String] The computed MAC tag.
    # @raise [ArgumentError] If data is given after the CMAC has already been finalized.
    def digest(data = nil)
      raise ArgumentError.new("CMAC has already been finalized") if data && @mac_tag
      return @mac_tag if @mac_tag

      update(data) if data
      @mac_tag = @aes_cbc.update(pad_last_block(@buffer)) # No need to call final because no padding is used
    end

    # Returns the computed MAC tag as a hex-encoded string.
    #
    # @param data [String] The data to update the CMAC computation with before finalizing.
    #   If nil, the CMAC computation is finalized without updating with any data.
    # @return [String] The computed MAC tag as a hex-encoded string.
    def hexdigest(data = nil)
      digest(data).unpack1("H*")
    end

    # Returns the computed MAC tag as a Base64-encoded string.
    #
    # @param data [String] The data to update the CMAC computation with before finalizing.
    #   If nil, the CMAC computation is finalized without updating with any data.
    # @return [String] The computed MAC tag as a Base64-encoded string.
    def base64digest(data = nil)
      [digest(data)].pack("m0")
    end

    # Verifies the given MAC tag against the computed MAC tag for the given data.
    #
    # @param tag [String] The MAC tag to verify.
    # @param data [String] The data to verify the MAC tag against.
    #   If nil, the MAC tag is verified against the current CMAC computation.
    # @return [Boolean] True if the MAC tag is verified. Raises otherwise.
    # @raise [TagMismatchError] If the MAC tag verification fails.
    def verify(tag, data = nil)
      if !secure_compare(tag, digest(data))
        raise TagMismatchError.new("MAC tag verification failed, the tags do not match")
      end
      true # Needs not be checked because an error is raised if the tags do not match
    end

    # Compares the CMAC instance with another CMAC instance. The comparison is
    # done by comparing the computed MAC tags. The comparison is done in constant
    # time to prevent timing attacks.
    #
    # @param other [Krypt::Cmac] The other CMAC instance to compare with.
    # @return [Boolean] True if the MAC tags are equal, false otherwise.
    def ==(other)
      return false unless Cmac === other
      return false unless digest.bytesize == other.digest.bytesize
      OpenSSL.fixed_length_secure_compare(digest, other.digest)
    end

    private

    def cipher_for_key(key, mode)
      algorithm = "AES-#{key.size * 8}-#{mode}"
      OpenSSL::Cipher.new(algorithm).tap do |cipher|
        cipher.encrypt
        cipher.key = key
        cipher.padding = 0  # Do not use padding
      end
    end

    def generate_subkeys(key)
      aes_ecb = cipher_for_key(key, :ECB)
      l = aes_ecb.update(BLOCK_OF_ZEROS) # No need to call final because no padding is used
      k1 = generate_subkey(l)
      k2 = generate_subkey(k1)
      [k1, k2, l]
    end

    def generate_subkey(bytes)
      msb = most_significant_bit_set?(bytes)
      k = shift_left(bytes)
      k.setbyte(-1, k.getbyte(-1) ^ RB) if msb
      k
    end

    def update_full_blocks(blocks)
      return if blocks.empty?
      @aes_cbc.update(blocks)
    end

    def pad_last_block(buffer)
      len = buffer.bytesize # 0 < len <= AES_BLOCK_SIZE

      if len == AES_BLOCK_SIZE
        xor_block(buffer, k1)
      else
        buffer << "\x80".b # Append 1 bit (0x80 in hex) with ASCII-8BIT encoding
        buffer << "\x00".b * (AES_BLOCK_SIZE - (len + 1)) # Pad the rest with 0 bits
        xor_block(buffer, k2)
      end
    end

    def shift_left(byte_string)
      bytes = byte_string.bytes
      carry = 0

      bytes.reverse_each.with_index do |byte, i|
        new_carry = (byte & 0x80) >> 7
        # Update bytes beginning from the end, so use negative index plus 1
        # i=0 => bytes[-1], i=1 => bytes[-2], etc.
        # Shift left, clear the LSB to ensure it is 0 with 0xFE (whose LSB is 0), and finally add carry
        bytes[-(i + 1)] = ((byte << 1) & 0xFE) | carry
        carry = new_carry
      end

      bytes.pack("C*") # Convert bytes back to a string
    end

    def most_significant_bit_set?(bytes)
      most_significant_bit(bytes) != 0
    end

    def most_significant_bit(bytes)
      bytes.unpack1("C") & 0x80
    end

    def xor_block(block, key)
      block.bytes.each_with_index.map { |b, i| b ^ key.getbyte(i) }.pack("C*")
    end

    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize
      OpenSSL.fixed_length_secure_compare(a, b)
    end
  end
end
