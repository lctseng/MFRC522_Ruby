require 'openssl'
require 'securerandom'

module Mifare
  module UltralightC
    
    # Using 16 bytes hex string for 3DES authentication
    def auth(key)
      # Convert hex to byte array
      key = [key].pack('H*')
      return :status_data_length_error if key.size != 16

      # Ask for authentication
      buffer = [CMD_3DES_AUTH, 0x00]
      status, received_data = @pcd.picc_transceive(buffer)
      return status if status != :status_ok
      return :status_unknown_data if received_data[0] != 0xAF

      # Use received data as IV for next transmission
      next_iv = received_data[1..8]

      # Cipher
      cipher = OpenSSL::Cipher.new('des-ede-cbc')
      cipher.key = key
      cipher.padding = 0

      # Decrypt challenge random number and rotate it by 8 bits
      cipher.decrypt
      cipher.iv = "\x00"*8
      challenge = received_data[1..8].pack('C*')
      challenge = cipher.update(challenge) + cipher.final
      challenge = challenge.bytes.rotate

      # Generate 8 bytes random number and encrypt the response 
      random_number = SecureRandom.random_bytes(8)
      cipher.encrypt
      cipher.iv = next_iv.pack('C*')
      response = cipher.update(random_number + challenge.pack('C*')) + cipher.final
      response = response.bytes

      # Receive verification
      buffer = [0xAF] + response
      status, received_data = @pcd.picc_transceive(buffer)
      return status if status != :status_ok
      return :status_unknown_data if received_data[0] != 0x00

      # Check if verification matches random_number rotated by 8 bits
      cipher.decrypt
      cipher.iv = response[-8..-1].pack('C*')
      verification = received_data[1..8].pack('C*')
      verification = cipher.update(verification) + cipher.final

      if random_number.bytes.rotate != verification.bytes
        halt
        return :status_auth_failed
      end

      return :status_ok
    end

    def write_des_key(key)
      # key should be 16 bytes long
      bytes = [key].pack('H*').unpack('C*')
      return :status_data_length_error if bytes.size != 16

      # Key1
      write(0x2C, bytes[4..7].reverse)
      write(0x2D, bytes[0..3].reverse)
      # Key2
      write(0x2E, bytes[12..15].reverse)
      write(0x2F, bytes[8..11].reverse)
    end

    def counter_increment(value)
      # you can set any value between 0x0000 to 0xFFFF on the first write (initialize)
      # after initialized, counter can only be incremented by 0x01 ~ 0x0F
      write(0x29, [value & 0xFF, (value >> 8) & 0xFF, 0x00, 0x00])
    end

    def enable_protection_from(block_addr)
      # authentication will be required from `block_addr` to 0x2F
      # valid value are from 0x03 to 0x30
      # set to 0x30 to disable memory protection
      write(0x2A, [block_addr & 0x3F, 0x00, 0x00, 0x00])
    end

    def set_protection_type(type)
      # set to 0 for read-write access restriction (default)
      # set to 1 for write access restriction
      write(0x2B, [type & 0x01, 0x00, 0x00, 0x00])
    end

  end
end
