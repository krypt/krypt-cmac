# Krypt::Cmac

[![Gem Version](https://badge.fury.io/rb/krypt-cmac.svg)](https://badge.fury.io/rb/krypt-cmac)

First off, don't use CMAC unless you really need to. HMAC is usually faster, more robust, and easier to use.
Only go for CMAC if it's already been decided and you need to work with it.

Krypt::Cmac provides implementations for all versions of the AES-CMAC algorithm as specified in:

- [NIST SP 800-38B](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf)
- [RFC 4493](https://tools.ietf.org/html/rfc4493)
- [RFC 4494](https://tools.ietf.org/html/rfc4494)
- [RFC 4615](https://tools.ietf.org/html/rfc4615)

It supports 128, 192, and 256-bit keys, variable length keys, and can handle streaming processing.
Only AES is supported as the underlying block cipher algorithm. The implementations offer the same
public API as `OpenSSL::HMAC` except for the `reset` method.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'krypt-cmac'
```

And then execute:

```bash
bundle install
```

If you aren't using `bundler` for managing dependencies, you may install the gem directly by executing:

```bash
gem install krypt-cmac
```

## Usage

### AES-CMAC with 128, 192 or 256 bits (NIST SP 800-38B, RFC 4493)

When using the default implementation, the size of the key determines the version of AES being used. This
implies that keys must be either 128, 192 or 256 bits long, resulting in AES-128-CMAC, AES-192-CMAC or
AES-256-CMAC tags. See below for variable key lengths.

```ruby
require 'krypt/cmac'

key = ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*")
message = ["6bc1bee22e409f96e93d7e117393172a"].pack("H*")

# One-shot computation
cmac = Krypt::Cmac.new(key)
tag = cmac.digest(message)

# Streaming computation
cmac = Krypt::Cmac.new(key)
cmac.update(message)
tag = cmac.digest
```

### AES-CMAC-96 (RFC 4494)

To generate CMAC tags that are 96 bits long instead of the default 128 bits, use `Krypt::Cmac::Cmac96`.
Note that CMAC-96 tags are simply regular tags truncated to 96 bits. If you need any other tag size
below 128 bits, you can truncate the regular tag manually.

```ruby
require 'krypt/cmac'

key = ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*")
message = ["6bc1bee22e409f96e93d7e117393172a"].pack("H*")

# AES-CMAC-96 one-shot computation
cmac = Krypt::Cmac::Cmac96.new(key)
tag = cmac.digest(message)

# AES-CMAC-96 streaming computation
cmac = Krypt::Cmac::Cmac96.new(key)
cmac.update(message)
tag = cmac.digest
```

### AES-CMAC-PRF-128 (RFC 4615)

If you need to generate CMAC tags from keys of varying lengths and not the usual 128, 192, or 256 bit
range, use AES-CMAC-PRF-128 as provided by `Krypt::Cmac::CmacPrf128`. It computes a regular AES-CMAC on the
key first and uses the 128 bit result as the actual key for CMAC computation. You might also use it if
you need an AES-128-CMAC tag for keys that are 192 or 256 bits long. Using regular AES-CMAC with such
keys would compute AES-192-CMAC and AES-256-CMAC tags respectively.

```ruby
require 'krypt/cmac'

key = ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*")
message = ["6bc1bee22e409f96e93d7e117393172a"].pack("H*")

# AES-CMAC-PRF-128 one-shot computation
cmac = Krypt::Cmac::CmacPrf128.new(key)
tag = cmac.digest(message)

# AES-CMAC-PRF-128 streaming computation
cmac = Krypt::Cmac::CmacPrf128.new(key)
cmac.update(message)
tag = cmac.digest
```

### Tag verification

Verifying a given tag means recomputing it and then comparing the two. However, it is crucial for security reasons
to avoid comparing them with `==` or similar comparisons subject to
[short-circuiting](https://en.wikipedia.org/wiki/Short-circuit_evaluation). To securely verify a tag, use:

```ruby
require 'krypt/cmac'

key = ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*")
message = ["6bc1bee22e409f96e93d7e117393172a"].pack("H*")
tag = ["070a16b46b4d4144f79bdd9dd04a287c"].pack("H*")

# Verifying a tag with data supplied to the method
cmac = Krypt::Cmac.new(key)
valid = cmac.verify(tag, message)

# Verifying a tag without data supplied to the method
cmac = Krypt::Cmac.new(key)
cmac.update(message)
begin
  valid = cmac.verify(tag)
  puts "Tag successfully verified"
rescue Krypt::Cmac::TagMismatchError => e
  # tag invalid
end
```

Even though the `verify` method returns `true` on successful verification, it still raises a
`Krypt::Cmac::TagMismatchError` on invalid tags. This ensures that invalid tags cannot go undetected if the
verifying code forgets to check for `true` explicitly.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can 
also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the 
version number in `lib/krypt/cmac/version.rb`, and then run `bundle exec rake release`, which will create a git tag for 
the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/krypt/krypt-cmac.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
