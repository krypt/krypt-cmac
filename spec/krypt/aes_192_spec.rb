RSpec.describe "Krypt::Cmac with AES-192 key" do
  include_context "String helpers"
  include_context "reference samples"

  let(:key) { hex_to_bin(ReferenceSamples::AES_192[:key]) }

  ReferenceSamples.sample_keys.each do |sample_key|
    sample = ReferenceSamples::AES_192[sample_key]
    context sample[:description] do
      let(:data) { hex_to_bin(sample[:data]) }
      let(:expected_mac) { hex_to_bin(sample[:tag]) }

      it_behaves_like "correct CMAC"
    end
  end
end
