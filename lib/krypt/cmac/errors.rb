module Krypt
  class Cmac
    # Raised when the CMAC is in an invalid state for the operation, e.g. when calling `update` after `digest`
    # or by supplying additional data to `digest` after finalization.
    class InvalidStateError < StandardError; end

    # Raised when MAC tag verification fails.
    class TagMismatchError < StandardError; end
  end
end
