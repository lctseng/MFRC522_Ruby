module Mifare
  class Ultralight < ::PICC

    def initialize(pcd, uid, sak)
      super
      @is_c = false

      # Check if Ultralight C
      status, received_data = @pcd.mifare_ultralight_3des_check
      if status == :status_ok
        extend UltralightC
        @is_c = true
      end
      resume_communication
    end

    def read(block_addr)
      buffer = [MFRC522::PICC_MF_READ, block_addr]

      status, received_data = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      return :status_ok, received_data
    end

    def write(page, send_data)
      return :status_data_length_error if send_data.size != 4

      # Page 2-15, each 4 bytes
      buffer = [MFRC522::PICC_UL_WRITE, page]
      buffer += send_data

      status = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      return :status_ok
    end

    def is_c?
      @is_c
    end

  end
end