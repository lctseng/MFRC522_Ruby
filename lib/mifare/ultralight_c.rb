module Mifare
  module UltralightC
    
    # Using 16 bytes hex string for 3DES authentication
    def auth(key)
      @pcd.mifare_ultralight_3des_authenticate(key)
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
