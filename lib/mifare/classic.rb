module Mifare
  class Classic < ::PICC

    def auth(block_addr, key = {})
      if key[:a]
        @pcd.mifare_crypto1_authenticate(MFRC522::PICC_MF_AUTH_KEY_A, block_addr, key[:a], @uid)
      elsif key[:b]
        @pcd.mifare_crypto1_authenticate(MFRC522::PICC_MF_AUTH_KEY_B, block_addr, key[:b], @uid)
      else
        :status_incorrect_input
      end
    end

    def deauth
      @pcd.mifare_crypto1_deauthenticate
    end

    def read(block_addr)
      buffer = [MFRC522::PICC_MF_READ, block_addr]

      status, received_data = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      return :status_ok, received_data
    end

    def write(block_addr, send_data)
      return :status_data_length_error if send_data.size != 16

      buffer = [MFRC522::PICC_MF_WRITE, block_addr]

      # Ask PICC if we can write to block_addr
      status = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      # Then start transfer our data
      status = @pcd.picc_transceive(send_data)
      return status if status != :status_ok

      return :status_ok
    end

    def read_value(block_addr)
      status, received_data = read(block_addr)
      return status if status != :status_ok
    
      value = (received_data[3] << 24) +
              (received_data[2] << 16) +
              (received_data[1] << 8) +
              received_data[0]
    
      return :status_ok, value
    end

    def write_value(block_addr, value)
      return :status_data_length_error if value.size > 4

      # Value block format
      #
      # byte 0..3:   32 bit value in little endian
      # byte 4..7:   copy of byte 0..3, with inverted bits (aka. XOR 255)
      # byte 8..11:  copy of byte 0..3
      # byte 12:     index of backup block (can be any value)
      # byte 13:     copy of byte 12 with inverted bits (aka. XOR 255)
      # byte 14:     copy of byte 12
      # byte 15:     copy of byte 13
      buffer = []
      buffer[0]  = value & 0xFF
      buffer[1]  = (value >> 8) & 0xFF
      buffer[2]  = (value >> 16) & 0xFF
      buffer[3]  = (value >> 24) & 0xFF
      buffer[4]  = ~buffer[0]
      buffer[5]  = ~buffer[1]
      buffer[6]  = ~buffer[2]
      buffer[7]  = ~buffer[3]
      buffer[8]  = buffer[0]
      buffer[9]  = buffer[1]
      buffer[10] = buffer[2]
      buffer[11] = buffer[3]
      buffer[12] = block_addr
      buffer[13] = ~block_addr
      buffer[14] = buffer[12]
      buffer[15] = buffer[13]
    
      write(block_addr, buffer)
    end

    # Increment: Increments the contents of a block and stores the result in the internal Transfer Buffer
    def increment(block_addr, delta)
      two_step(MFRC522::PICC_MF_INCREMENT, block_addr, delta)
    end

    # Decrement: Decrements the contents of a block and stores the result in the internal Transfer Buffer
    def decrement(block_addr, delta)
      two_step(MFRC522::PICC_MF_DECREMENT, block_addr, delta)
    end

    # Restore: Moves the contents of a block into the internal Transfer Buffer
    def restore(block_addr)
      two_step(MFRC522::PICC_MF_RESTORE, block_addr, 0)
    end

    # Transfer: Writes the contents of the internal Transfer Buffer to a value block
    def transfer(block_addr)
      buffer = [MFRC522::PICC_MF_TRANSFER, block_addr]

      status = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      return :status_ok
    end

    private

    # Helper for increment, decrement, and restore command
    def two_step(command, block_addr, value)
      return :status_data_length_error if value.size > 4

      buffer = [command, block_addr]
      send_data = [ # Split integer into array of bytes
        value & 0xFF,
        (value >> 8) & 0xFF,
        (value >> 16) & 0xFF,
        (value >> 24) & 0xFF
      ]
      
      # Ask PICC if we can write to block_addr
      status = @pcd.picc_transceive(buffer)
      return status if status != :status_ok

      # Then start transfer our data
      status = @pcd.picc_transceive(send_data, true) # Accept timeout
      return status if status != :status_ok

      return :status_ok
    end

  end
end