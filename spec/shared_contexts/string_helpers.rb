RSpec.shared_context "String helpers" do
  def hex_to_bin(hex)
    [hex].pack("H*")
  end

  def bin_to_hex(bin)
    bin.unpack1("H*")
  end

  def b64_to_bin(b64)
    b64.unpack1("m")
  end

  def bin_to_b64(bin)
    [bin].pack("m0")
  end
end
