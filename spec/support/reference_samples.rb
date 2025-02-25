require "krypt/cmac"

module ReferenceSamples
  module_function

  def sample_keys
    @_keys ||= (AES_128.keys - %i[key])
  end

  # Taken from /res/AES_CMAC.pdf
  AES_128 = {
    key: "2b7e151628aed2a6abf7158809cf4f3c",
    empty: {
      description: "empty message (len 0)",
      data: "",
      tag: "bb1d6929e95937287fa37d129b756746"
    },
    single_block: {
      description: "single block message (i.e. len 16)",
      data: "6bc1bee22e409f96e93d7e117393172a",
      tag: "070a16b46b4d4144f79bdd9dd04a287c"
    },
    non_multiple_block: {
      description: "with a message that is not a multiple of the block size, e.g. len 20",
      data: "6bc1bee22e409f96e93d7e117393172aae2d8a57",
      tag: "7d85449ea6ea19c823a7bf78837dfade"
    },
    multiple_block: {
      description: "with a message that is a multiple of the block size, e.g. len 64",
      data: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      tag: "51f0bebf7e3b9d92fc49741779363cfe"
    }
  }

  # Taken from /res/AES_CMAC.pdf
  AES_192 = {
    key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    empty: {
      description: "empty message (len 0)",
      data: "",
      tag: "d17ddf46adaacde531cac483de7a9367"
    },
    single_block: {
      description: "single block message (i.e. len 16)",
      data: "6bc1bee22e409f96e93d7e117393172a",
      tag: "9e99a7bf31e710900662f65e617c5184"
    },
    non_multiple_block: {
      description: "with a message that is not a multiple of the block size, e.g. len 20",
      data: "6bc1bee22e409f96e93d7e117393172aae2d8a57",
      tag: "3d75c194ed96070444a9fa7ec740ecf8"
    },
    multiple_block: {
      description: "with a message that is a multiple of the block size, e.g. len 64",
      data: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      tag: "a1d5df0eed790f794d77589659f39a11"
    }
  }

  # Taken from /res/AES_CMAC.pdf
  AES_256 = {
    key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    empty: {
      description: "empty message (len 0)",
      data: "",
      tag: "028962f61b7bf89efc6b551f4667d983"
    },
    single_block: {
      description: "single block message (i.e. len 16)",
      data: "6bc1bee22e409f96e93d7e117393172a",
      tag: "28a7023f452e8f82bd4bf28d8c37c35c"
    },
    non_multiple_block: {
      description: "with a message that is not a multiple of the block size, e.g. len 20",
      data: "6bc1bee22e409f96e93d7e117393172aae2d8a57",
      tag: "156727dc0878944a023c1fe03bad6d93"
    },
    multiple_block: {
      description: "with a message that is a multiple of the block size, e.g. len 64",
      data: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      tag: "e1992190549f6ed5696a2c056c315410"
    }
  }

  # Taken from RFC 4494
  AES_CMAC_96 = {
    key: "2b7e151628aed2a6abf7158809cf4f3c",
    empty: {
      description: "empty message (len 0)",
      data: "",
      tag: "bb1d6929e95937287fa37d12"
    },
    single_block: {
      description: "single block message (i.e. len 16)",
      data: "6bc1bee22e409f96e93d7e117393172a",
      tag: "070a16b46b4d4144f79bdd9d"
    },
    non_multiple_block: {
      description: "with a message that is not a multiple of the block size, e.g. len 40",
      data: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
      tag: "dfa66747de9ae63030ca3261"
    },
    multiple_block: {
      description: "with a message that is a multiple of the block size, e.g. len 64",
      data: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      tag: "51f0bebf7e3b9d92fc497417"
    }
  }

  # Taken from RFC 4615
  AES_PRF_128 = {
    data: "000102030405060708090a0b0c0d0e0f10111213",
    key_length_18: {
      key: "000102030405060708090a0b0c0d0e0fedcb",
      description: "key length 18",
      tag: "84a348a4a45d235babfffc0d2b4da09a"
    },
    key_length_16: {
      key: "000102030405060708090a0b0c0d0e0f",
      description: "key length 16",
      tag: "980ae87b5f4c9c5214f5b6a8455e4c2d"
    },
    key_length_10: {
      key: "00010203040506070809",
      description: "key length 10",
      tag: "290d9e112edb09ee141fcf64c0b72f3d"
    }
  }
end
