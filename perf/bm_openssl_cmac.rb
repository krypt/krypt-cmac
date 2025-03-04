require "benchmark"
require "openssl/cmac"
require_relative "../lib/krypt/cmac"

key = ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*")
short_message = "\x00"
block_message = ["6bc1bee22e409f96e93d7e117393172a"].pack("H*")
long_message = ["6bc1bee22e409f96e93d7e117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172a117393172aff"].pack("H*")
cmac = Krypt::Cmac.new(key)
ossl_cmac = OpenSSL::CMAC.new("AES", key)

n = 1_000_000
Benchmark.bm do |x|
  x.report("Krypt::Cmac#update short_message:") { n.times { cmac.update(short_message) } }
  x.report("OpenSSL::CMAC#update short_message:") { n.times { ossl_cmac.update(short_message) } }
  x.report("Krypt::Cmac#update block_message:") { n.times { cmac.update(block_message) } }
  x.report("OpenSSL::CMAC#update block_message:") { n.times { ossl_cmac.update(block_message) } }
  x.report("Krypt::Cmac#update long_message:") { n.times { cmac.update(long_message) } }
  x.report("OpenSSL::CMAC#update long_message:") { n.times { ossl_cmac.update(long_message) } }
end
