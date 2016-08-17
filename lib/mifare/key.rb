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
    end

    def encrypt(data, cbc_mode = :send)
      @cipher.encrypt
      
      cbc_crypt(data, cbc_mode)
    end

    def decrypt(data, cbc_mode = :receive)
      @cipher.decrypt

      cbc_crypt(data, cbc_mode)
    end

    def clear_iv
      @cipher_iv = "\x00" * @block_size
    end

    def generate_cmac_subkeys
      r = (@block_size == 8) ? 0x1B : 0x87
      data = Array.new(@block_size, 0)

      clear_iv
      data = encrypt(data, :receive)

      @cmac_subkey1 = bit_shift_left(data)
      @cmac_subkey1[-1] ^= r if data[0] & 0x80 != 0

      @cmac_subkey2 = bit_shift_left(@cmac_subkey1)
      @cmac_subkey2[-1] ^= r if @cmac_subkey1[0] & 0x80 != 0
    end

    def calculate_cmac(data)
      if @cmac_subkey1.nil? || @cmac_subkey2.nil?
        raise 'Generate subkeys before calculating CMAC'
      end

      # Separate from input object
      data = data.dup

      if data.size == 0 || data.size % @block_size != 0
        # padding with byte: 0x80, 0x00, 0x00.....
        data << 0x80
        until data.size % @block_size == 0
          data << 0x00
        end

        key = @cmac_subkey2
      else
        key = @cmac_subkey1
      end

      # XOR last data block with selected CMAC subkey
      data = data[0...-@block_size] + data[-@block_size..-1].zip(key).map{|x, y| x ^ y }
      encrypt(data)

      @cipher_iv.bytes
    end

    private

    def init_cipher
      @cipher = OpenSSL::Cipher.new(@cipher_suite)
      @cipher.padding = 0
    end

    def set_key_data(key_type, key, version)
      # Convert hex string to byte array
      key = [key].pack('H*').bytes if key.is_a?(String)
      @key_size = key.size

      if key_type == :des
        if @key_size != 8 && @key_size != 16 && @key_size != 24
          raise UnexpectedDataError, 'Incorrect key length'
        end

        # data block size for DES is 8 bytes
        @block_size = 8

        @key = store_key_version(key, version)

        if @key_size == 8
          @key += @key
          @cipher_suite = 'des-ede-cbc'
        elsif @key_size == 16
          @cipher_suite = 'des-ede-cbc'
        elsif @key_size == 24
          @cipher_suite = 'des-ede3-cbc'
        end

      elsif key_type == :aes
        if @key_size != 16
          raise UnexpectedDataError, 'Incorrect key length'
        end

        # data block size for AES is 16 bytes
        @block_size = 16
        @key = key
        @cipher_suite = 'aes-128-cbc'
      else
        raise UnexpectedDataError, 'Unknown key type'
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

    def cbc_crypt(data, mode)
      @cipher.key = @key
      @cipher.iv = @cipher_iv
      data = data.pack('C*') # Convert byte array to binary

      if mode == :send
        output_data = @cipher.update(data) + @cipher.final
        @cipher_iv = output_data[-@block_size..-1]

        output_data.bytes
      elsif mode == :receive
        @cipher_iv = data[-@block_size..-1]
        output_data = @cipher.update(data) + @cipher.final

        output_data.bytes
      else
        raise UnexpectedDataError, 'Unknown CBC mode'
      end
    end

    def bit_shift_left(data)
      data.map.with_index do |value, index|
        value = (value << 1) & 0xFF
        if subsequent = data[index+1]
          value |= (subsequent >> 7) & 0x01
        end
        value
      end
    end
  end
end
