module Mifare
  class Ultralight < ::PICC

    CMD_READ        = 0x30  # Reads four 4 byte page from the PICC.
    CMD_WRITE       = 0xA2  # Writes one 4 byte page to the PICC.
    CMD_3DES_AUTH   = 0x1A  # Ultralight C 3DES Authentication.

    def initialize(pcd, uid, sak)
      super
      @is_c = false

      # Check if Ultralight C
      status, _received_data = check_3des_capability
      if status == :status_ok
        extend UltralightC
        @is_c = true
      end
      resume_communication
    end

    def read(block_addr)
      buffer = [CMD_READ, block_addr]

      status, received_data = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      return :status_ok, received_data
    end

    def write(page, send_data)
      return :status_data_length_error if send_data.size != 4

      # Page 2-15, each 4 bytes
      buffer = [CMD_WRITE, page]
      buffer += send_data

      status = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      return :status_ok
    end

    def is_c?
      @is_c
    end

    # Check if PICC support Ultralight 3DES command
    def check_3des_capability
      # Ask for authentication
      buffer = [CMD_3DES_AUTH, 0x00]
      status, received_data = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      return :status_ok, received_data
    end
    
  end
end