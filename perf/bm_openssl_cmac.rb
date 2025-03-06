require "benchmark"
require "openssl/cmac"
require_relative "../lib/krypt/cmac"

key = ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*")
short_message = "\x00"
block_message = ["6bc1bee22e409f96e93d7e117393172a"].pack("H*")
long_message = ["6bc1bee22e409f96e93d7e117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172aff"].pack("H*")
very_long_message = long_message * 100

n = 1_000_000
Benchmark.bm do |x|
  cmac = Krypt::Cmac.new(key)
  ossl_cmac = OpenSSL::CMAC.new("AES", key)

  x.report("Krypt::Cmac#update short_message:") { n.times { cmac.update(short_message) } }
  x.report("OpenSSL::CMAC#update short_message:") { n.times { ossl_cmac.update(short_message) } }
  x.report("Krypt::Cmac#update block_message:") { n.times { cmac.update(block_message) } }
  x.report("OpenSSL::CMAC#update block_message:") { n.times { ossl_cmac.update(block_message) } }
  x.report("Krypt::Cmac#update long_message:") { n.times { cmac.update(long_message) } }
  x.report("OpenSSL::CMAC#update long_message:") { n.times { ossl_cmac.update(long_message) } } 
end


n = 100_000
Benchmark.bm do |x|
  x.report("Krypt::Cmac#digest short_message:") { n.times { Krypt::Cmac.new(key).digest(short_message) } }
  x.report("OpenSSL::CMAC#digest short_message:") { n.times { OpenSSL::CMAC.new("AES", key).update(short_message).digest } }
  x.report("Krypt::Cmac#digest block_message:") { n.times { Krypt::Cmac.new(key).digest(block_message) } }
  x.report("OpenSSL::CMAC#digest block_message:") { n.times { OpenSSL::CMAC.new("AES", key).update(block_message).digest } }
  x.report("Krypt::Cmac#digest long_message:") { n.times { Krypt::Cmac.new(key).digest(long_message) } }
  x.report("OpenSSL::CMAC#digest long_message:") { n.times { OpenSSL::CMAC.new("AES", key).update(long_message).digest } }
  x.report("Krypt::Cmac#digest very long_message:") { n.times { Krypt::Cmac.new(key).digest(very_long_message) } }
  x.report("OpenSSL::CMAC#digest very long_message:") { n.times { OpenSSL::CMAC.new("AES", key).update(very_long_message).digest } }
end
