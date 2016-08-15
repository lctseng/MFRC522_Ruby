module Mifare
  class Key
    attr_reader :type
    attr_reader :cipher_suite
    attr_reader :key_size
    attr_reader :version

    def initialize(type, key, version = 0x00)
      @type = type
      set_key_data(type, key, version)
      clear_iv
      init_cipher
      init_cmac
    end

    def encrypt(data, iv = nil)
      @cipher.encrypt
      @cipher.iv = iv || @cipher_iv

      data = data.pack('C*') # Convert byte array to binary
      enc_data = @cipher.update(data) + @cipher.final # Encrypt data 
      @cipher_iv = enc_data[-@block_size..-1] # Save it as iv for next operation

      enc_data.bytes # Convert binary back to byte array
    end

    def decrypt(data, iv = nil)
      @cipher.decrypt
      @cipher.iv = iv || @cipher_iv

      data = data.pack('C*') # Convert byte array to binary
      @cipher_iv = data[-@block_size..-1] # Store it as iv for next operation

      (@cipher.update(data) + @cipher.final).bytes # Decrypt data and convert back to byte array
    end

    def clear_iv
      @cipher_iv = "\x00" * @block_size
    end

    def generate_cmac(data)
      @cmac.generate(data)
    end

    private

    def init_cipher
      @cipher = OpenSSL::Cipher.new(@cipher_suite)
      @cipher.key = @key
      @cipher.padding = 0
    end

    def init_cmac
      key = @key
      key *= 2 if @key_size == 8
      @cmac = OpenSSL::CMAC.new(key)
    end

    def set_key_data(key_type, key, version)
      # Convert hex string to byte array
      key = [key].pack('H*').bytes if key.is_a?(String)
      @key_size = key.size

      if key_type == :des
        raise 'Incorrect key length' if @key_size != 8 && @key_size != 16 && @key_size != 24

        # data block size for DES is 8 bytes
        @block_size = 8

        @key = store_key_version(key, version)

        if @key_size == 8
          @cipher_suite = 'des-cbc'
        elsif @key_size == 16
          @cipher_suite = 'des-ede-cbc'
        elsif @key_size == 24
          @cipher_suite = 'des-ede3-cbc'
        end

      elsif key_type == :aes
        raise 'Incorrect key length' if @key_size != 16

        # data block size for AES is 16 bytes
        @block_size = 16
        @key = key
        @cipher_suite = 'aes-128-cbc'
      else
        raise 'Unknown key type'
      end

      @key = @key.pack('C*')
      @version = version
    end

    # Store key version in LSB parity bit of DES key
    def store_key_version(key, version)
      mask = 0x80
      key.map.with_index do |key_byte, index|
        if (index < 8) && (version & (mask >> index) != 0)
          parity = 1
        else
          parity = 0
        end
        (key_byte & 0xFE) | parity
      end
    end
  end
end
