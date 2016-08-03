module Mifare
  class Ultralight < Base

    def read(block_addr)
      buffer = [MFRC522::PICC_MF_READ, block_addr]

      status, received_data = @pcd.mifare_transceive(buffer)
      return status if status != :status_ok

      return :status_ok, received_data
    end

    def write(page, send_data)
      return :status_data_length_error if send_data.size != 4

      # Page 2-15, each 4 bytes
      buffer = [MFRC522::PICC_UL_WRITE, page]
      buffer += send_data

      status = @pcd.mifare_transceive(buffer)
      return status if status != :status_ok

      return :status_ok
    end

  end
end