RSpec.describe Krypt::Cmac::Prf128 do
  include_context "String helpers"
  include_context "reference samples"

  let(:data) { hex_to_bin(ReferenceSamples::AES_PRF_128[:data]) }

  (ReferenceSamples::AES_PRF_128.keys - %i[data]).each do |sample_key|
    sample = ReferenceSamples::AES_PRF_128[sample_key]
    context sample[:description] do
      let(:key) { hex_to_bin(sample[:key]) }
      let(:expected_mac) { hex_to_bin(sample[:tag]) }

      it_behaves_like "correct AES-CMAC-PRF-128"
    end
  end
end
