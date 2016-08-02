module Mifare
  class UltralightC < Ultralight
    
    # Using 16 bytes hex string for 3DES authentication
    def auth(key)
      @pcd.mifare_3des_authenticate(key)
    end

    def write_des_key(key)
      bytes = [key].pack('H*').unpack('C*')
      return :status_data_length_error if bytes.size != 16

      # Key1
      write(0x2C, bytes[4..7].reverse)
      write(0x2D, bytes[0..3].reverse)
      # Key2
      write(0x2E, bytes[12..15].reverse)
      write(0x2F, bytes[8..11].reverse)
    end

  end
end