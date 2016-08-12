module Mifare
  class Ultralight < ::PICC

    CMD_READ        = 0x30  # Reads 4 pages(16 bytes) from the PICC.
    CMD_WRITE       = 0xA2  # Writes 1 page(4 bytes) to the PICC.
    CMD_3DES_AUTH   = 0x1A  # Ultralight C 3DES Authentication.

    def initialize(pcd, uid, sak)
      super
      @model_c = false

      # Check if Ultralight C
      if support_3des_auth?
        extend UltralightC
        @model_c = true
      end
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
      buffer.concat(send_data)

      status = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      return :status_ok
    end

    def model_c?
      @model_c
    end

    private

    # Check if PICC support Ultralight 3DES command
    def support_3des_auth?
      # Ask for authentication
      buffer = [CMD_3DES_AUTH, 0x00]
      status, received_data = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      resume_communication

      status == :status_ok
    end
    
  end
end