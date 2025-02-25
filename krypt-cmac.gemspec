require_relative "lib/krypt/cmac/version"

Gem::Specification.new do |spec|
  spec.name = "krypt-cmac"
  spec.version = Krypt::Cmac::VERSION
  spec.authors = ["Martin Boßlet"]
  spec.email = ["martin.bosslet@gmail.com"]

  spec.summary = "AES-CMAC as specified in RFC 4493 and NIST SP 800-38B"
  spec.description = "An implementation AES-CMAC for 128, 192, and 256 bit keys as specified in NIST SP 800-38B and RFC 4493, capable of streaming processing."
  spec.homepage = "https://github.com/krypt/krypt-cmac"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files = Dir.glob("{lib,spec}/**/*") + %w[README.md LICENSE]
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
