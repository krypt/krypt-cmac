require "krypt/cmac"

RSpec.shared_context "reference samples" do
  include_context "String helpers"

  shared_examples "correct computation" do
    subject {
      described_class.new(key)
    }

    it { expect(subject.digest(data)).to eq(expected_mac) }

    it "computes the correct digest when using update" do
      expect(subject.update(data).digest).to eq(expected_mac)
    end

    it "computes the correct digest when using <<" do
      subject << data
      expect(subject.digest).to eq(expected_mac)
    end

    it "computes the correct hexdigest" do
      expect(subject.hexdigest(data)).to eq(bin_to_hex(expected_mac))
    end

    it "computes the correct base64digest" do
      expect(subject.base64digest(data)).to eq(bin_to_b64(expected_mac))
    end

    it "returns true when verifying the correct MAC" do
      expect(subject.verify(expected_mac, data)).to be true
    end

    it "returns true when verifying the correct MAC without supplying data to `verify`" do
      expect(subject.update(data).verify(expected_mac)).to be true
    end

    it "returns true when comparing two equal CMAC instances" do
      expect(subject.update(data)).to eq(described_class.new(key).update(data))
    end

    it "returns false when comparing two different CMAC instances" do
      expect(subject.update("nope")).not_to eq(described_class.new(key).update(data))
    end

    it "raises an error when verifying an incorrect MAC" do
      expect { subject.verify(Krypt::Cmac::BLOCK_OF_ZEROS, data) }.to raise_error(Krypt::Cmac::TagMismatchError, "MAC tag verification failed, the tags do not match")
    end

    it "computes the correct MAC when updating the data in chunks" do
      (1..(data.size)).each do |i|
        mac = described_class.new(key)
        data.chars.each_slice(i) { |slice| mac.update(slice.join) }
        expect(mac.digest).to eq(expected_mac)
      end
    end
  end

  shared_examples "correct CMAC" do
    let(:described_class) { Krypt::Cmac }
    include_examples "correct computation"
  end

  shared_examples "correct AES-CMAC-96" do
    let(:described_class) { Krypt::Cmac::Cmac96 }
    include_examples "correct computation"
  end

  shared_examples "correct AES-CMAC-PRF-128" do
    let(:described_class) { Krypt::Cmac::CmacPrf128 }
    include_examples "correct computation"
  end
end
