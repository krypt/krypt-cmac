require "simplecov"
SimpleCov.start

require "krypt/cmac"

RSpec.configure do |config|
  # Include shared contexts
  Dir[File.join(__dir__, "shared_contexts", "**", "*.rb")].each { |f| require f }
  # Include all support files
  Dir[File.join(__dir__, "support", "**", "*.rb")].each { |f| require f }

  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
