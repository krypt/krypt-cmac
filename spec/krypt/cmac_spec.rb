RSpec.describe Krypt::Cmac do
  include_context "String helpers"

  it "has a version number" do
    expect(Krypt::Cmac::VERSION).not_to be nil
  end

  context "general usage" do
    let(:sample) { ReferenceSamples::AES_128[:single_block] }
    let(:key) { hex_to_bin(ReferenceSamples::AES_128[:key]) }
    let(:data) { hex_to_bin(sample[:data]) }
    let(:tag) { hex_to_bin(sample[:tag]) }

    subject { Krypt::Cmac.new(key) }

    it "initializes with a key" do
      expect(subject.key).to eq(key)
    end

    it "updates with data and allows chaining" do
      expect { subject.update(data).update(data) }.not_to raise_error
    end

    it "raises an error if update is called after digest" do
      subject.digest(data)
      expect { subject.update(data) }.to raise_error(Krypt::Cmac::InvalidStateError, "CMAC has already been finalized")
    end

    it "raises an error if digest is called with data after finalization" do
      subject.digest(data)
      expect { subject.digest(data) }.to raise_error(ArgumentError, "CMAC has already been finalized")
    end

    it "returns the computed MAC tag if digest is called multiple times" do
      subject.update(data)
      tag1 = subject.digest
      tag2 = subject.digest
      expect(tag1).to eq(tag2)
      expect(tag1).to eq(tag)
    end

    it "returns the correct MAC tag when updating and calling digest without arguments" do
      computed_tag = subject.update(data).digest
      expect(computed_tag).to eq(tag)
    end

    it "returns the correct MAC tag when calling digest with the data as an argument" do
      computed_tag = subject.digest(data)
      expect(computed_tag).to eq(tag)
    end
  end

  context "initialization with different key sizes" do
    subject { Krypt::Cmac.new(key) }

    shared_examples "correct key" do
      it { expect(subject.key).to eq(key) }
    end

    context "128-bit key" do
      let(:key) { hex_to_bin(ReferenceSamples::AES_128[:key]) }
      it_behaves_like "correct key"
    end

    context "192-bit key" do
      let(:key) { hex_to_bin(ReferenceSamples::AES_192[:key]) }
      it_behaves_like "correct key"
    end

    context "256-bit key" do
      let(:key) { hex_to_bin(ReferenceSamples::AES_256[:key]) }
      it_behaves_like "correct key"
    end

    context "invalid key size" do
      let(:key) { hex_to_bin("invalidkeysize") }
      it "raises ArgumentError" do
        expect { subject }.to raise_error(ArgumentError, "Key must be 128, 192, or 256 bits long")
      end
    end
  end
end
