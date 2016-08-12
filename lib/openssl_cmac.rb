# This is an implementation of AES-CMAC Algorithm:
# http://tools.ietf.org/html/rfc4493
#
# OpenSSL version > 1.0.1 already has a native implementation of CMAC
# but there are no corresponding bindings in Ruby OpenSSL standard library

# This file is originally distributed under license MIT
# Author: Maxim Chechel
# Repo: https://github.com/hexdigest/openssl-cmac/blob/master/lib/openssl_cmac.rb
#
# Changes made to this file:
# Fixed `Encoding::CompatibilityError` on padding string in `generate`

require 'openssl'

module OpenSSL
  class CMAC
    CONST_ZERO = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".force_encoding('ASCII-8BIT')
    CONST_RB = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87]

    # key - base 128 bit AES key
    def initialize(key)
      @key = key
      @k1, @k2 = CMAC.gen_subkeys(@key)
    end

    def generate(data)
      data8 = data.dup.force_encoding('ASCII-8BIT')

      xor_key = @k1
      unless data8.size > 0 && 0 == data8.size % 16
        xor_key = @k2
        padding = "\x80"
        padding << "\x00" * (15 - data8.size % 16)
        data8 << padding.force_encoding('ASCII-8BIT')
      end

      data8[-16, 16].unpack('C*').each_with_index do |e, i| 
        data8[data8.size - 16 + i] = (e ^ xor_key[i]).chr
      end

      cipher = Cipher::AES.new(128, :CBC)
      cipher.encrypt
      cipher.key = @key

      cipher.update(data8)[-16, 16]
    end

    def verify(data, cmac)
      generate(data) == cmac
    end

    def self.gen_subkeys(key)
      cipher = Cipher::AES.new(128, :ECB)
      cipher.encrypt
      cipher.key = key

      k1 = (cipher.update(CONST_ZERO)).unpack('C*')
      xor_flag = k1[0] >= 0x80

      k2 = Array.new(16)

      k1.each_with_index {|e, i| 
        lsb = i == 15 ? 0 : (k1[i+1] & 0x80) / 0x80
        k1[i] = (k1[i] << 1) % 256 | lsb
        k1[i] ^= CONST_RB[i] if xor_flag

        lsb = i == 15 ? 0 : (k1[i+1] << 1 & 0x80) / 0x80
        k2[i] = (k1[i] << 1) % 256 | lsb
        k2[i] ^= CONST_RB[i] if k1[0] >= 0x80
      }

      [k1, k2]
    end
  end
end