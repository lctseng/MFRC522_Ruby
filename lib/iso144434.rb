class ISO144434 < PICC

  FSCI_to_FSC = { 0 => 16, 1 => 24, 2 => 32, 3 => 40, 4 => 48,
                  5 => 64, 6 => 96, 7 => 128, 8 => 256 }

  def initialize(pcd, uid, sak)
    super

    @cid = 0x00 # We don't support CID
    @fsc = 16 # Assume PICC only supports 16 bytes frame
    @fwt = 256 # 77.33ms(256 ticks) default frame waiting time

    @supt_cid = false
    @supt_nad = false
  end

  # ISO/IEC 14443-4 select
  def select
    # Send RATS (Request for Answer To Select)
    buffer = [MFRC522::PICC_ISO_RATS, 0x50 | @cid]
    status, received_data = @pcd.picc_transceive(buffer)
    return status if status != :status_ok

    dr, ds = process_ats(received_data)

    # Send PPS (Protocol and Parameter Selection Request)
    buffer = [MFRC522::PICC_ISO_PPS | @cid, 0x11, (ds << 2) | dr]
    status, received_data = @pcd.picc_transceive(buffer)
    return status if status != :status_ok
    return :status_unknown_data if received_data[0] != (0xD0 | @cid)

    # Set PCD baud rate
    @pcd.write_spi(MFRC522::TxModeReg, (dr << 4))
    @pcd.write_spi(MFRC522::RxModeReg, (ds << 4))

    return :status_ok
  end

  # Send S(DESELECT)
  def deselect
    
  end

  # Gether information from ATS (Answer to Select)
  def process_ats(ats)
    position = 1
    t0 = ats[position]
    fsci = t0 & 0x0F
    y1 = (t0 >> 4) & 0x07
    @fsc = FSCI_to_FSC[fsci]
    dr = 0
    ds = 0

    # Set baud rate
    if y1 & 0x01 != 0
      position += 1
      ta = ats[position]
      dr = ta & 0x07 # PCD to PICC baud rate
      ds = (ta >> 4) & 0x07 # PICC to PCD baud rate

      # Convert fastest baud rate to PCD setting
      dr = convert_iso_baud_rate_to_pcd_setting(dr)
      ds = convert_iso_baud_rate_to_pcd_setting(ds)
    end

    # Set timeout
    if y1 & 0x02 != 0
      position += 1
      tb = ats[position]
      fwi = (tb >> 4) & 0x0F
      sgfi = tb & 0x0F

      @fwt = (1 << fwi)
      sgft = (1 << sgfi)

      # PICC requested frame waiting time
      @pcd.internal_timer(@fwt)
    end

    # Get info about CID or NAD
    if y1 & 0x04 != 0
      position += 1
      tc = ats[position]
      
      @supt_cid = true if tc & 0x02 != 0
      @supt_nad = true if tc & 0x01 != 0
    end

    # PICC requested guard time before going to next step
    sleep 0.000302 * sgft

    return dr, ds
  end

  # Wrapper for handling ISO protocol
  def transceive(send_data)
    # Split data according to PICC's spec
    chained_data = send_data.each_slice(@fsc - 5).to_a
    pcb = 0x02

    # Send chained data
    while !chained_data.empty?
      pcb &= 0xEF # reset chaining indicator
      pcb |= 0x10 if chained_data.size > 1
      data = chained_data.shift

      buffer = [pcb] + data

      finished = false
      while !finished
        status, received_data = handle_wtx(buffer)
        return status if status != :status_ok

        r_pcb = received_data[0]

        # Check ACK
        if r_pcb & 0xF6 == 0xA2
          finished = true if (pcb & 0x01) == (r_pcb & 0x01)
        else
          finished = true
        end
      end

      pcb ^= 1 # toggle block number for next frame
    end

    return :status_ok, received_data
  end

  def handle_wtx(data)
    3.times do
      status, received_data = @pcd.picc_transceive(data)
      return status if status != :status_ok
      
      pcb = received_data[0]

      # WTX detected
      if pcb & 0xF7 == 0xF2
        inf_position = (pcb & 0x08 != 0) ? 2 : 1
        wtxm = received_data[inf_position] & 0x3F

        # Set temporary timer
        @pcd.internal_timer(@fwt * wtxm)

        # Reply WTX using received data
        data = received_data
      else
        # Set timer back to FWT
        @pcd.internal_timer(@fwt)

        return :status_ok, received_data
      end
    end

    return :status_picc_timeout
  end

  private

  def convert_iso_baud_rate_to_pcd_setting(value)
    x = (value >> 2) & 0x01
    y = (value >> 1) & 0x01
    z = value & 0x01

    ((x | y) << 1) + (x | ( ~y & z ))
  end

end