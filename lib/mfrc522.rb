require 'pi_piper'
include PiPiper

class Mfrc522

  # PICC commands used by the PCD to manage communication with several PICCs (ISO 14443-3, Type A, section 6.4)
  PICC_REQA           = 0x26  # REQuest command, Type A. Invites PICCs in state IDLE to go to READY and prepare for anticollision or selection. 7 bit frame.
  PICC_WUPA           = 0x52  # Wake-UP command, Type A. Invites PICCs in state IDLE and HALT to go to READY(*) and prepare for anticollision or selection. 7 bit frame.
  PICC_CT             = 0x88  # Cascade Tag. Not really a command, but used during anti collision.
  PICC_SEL_CL1        = 0x93  # Anti collision/Select, Cascade Level 1
  PICC_SEL_CL2        = 0x95  # Anti collision/Select, Cascade Level 2
  PICC_SEL_CL3        = 0x97  # Anti collision/Select, Cascade Level 3
  PICC_HLTA           = 0x50  # HaLT command, Type A. Instructs an ACTIVE PICC to go to state HALT.
  # The commands used for MIFARE Classic (from http://www.mouser.com/ds/2/302/MF1S503x-89574.pdf, Section 9)
  # Use PCD_MFAuthent to authenticate access to a sector, then use these commands to read/write/modify the blocks on the sector.
  # The read/write commands can also be used for MIFARE Ultralight.
  PICC_MF_AUTH_KEY_A  = 0x60  # Perform authentication with Key A
  PICC_MF_AUTH_KEY_B  = 0x61  # Perform authentication with Key B
  PICC_MF_READ        = 0x30  # Reads one 16 byte block from the authenticated sector of the PICC. Also used for MIFARE Ultralight.
  PICC_MF_WRITE       = 0xA0  # Writes one 16 byte block to the authenticated sector of the PICC. Called "COMPATIBILITY WRITE" for MIFARE Ultralight.
  PICC_MF_DECREMENT   = 0xC0  # Decrements the contents of a block and stores the result in the internal data register.
  PICC_MF_INCREMENT   = 0xC1  # Increments the contents of a block and stores the result in the internal data register.
  PICC_MF_RESTORE     = 0xC2  # Reads the contents of a block into the internal data register.
  PICC_MF_TRANSFER    = 0xB0  # Writes the contents of the internal data register to a block.
  # The commands used for MIFARE Ultralight (from http://www.nxp.com/documents/data_sheet/MF0ICU1.pdf, Section 8.6)
  # The PICC_MF_READ and PICC_MF_WRITE can also be used for MIFARE Ultralight.
  PICC_UL_WRITE       = 0xA2  # Writes one 4 byte page to the PICC.

  # PCD commands
  PCD_Idle          = 0x00  # no action, cancels current command execution
  PCD_Mem           = 0x01  # stores 25 bytes into the internal buffer
  PCD_GenRandomID   = 0x02  # generates a 10-byte random ID number
  PCD_CalcCRC       = 0x03  # activates the CRC coprocessor or performs a self test
  PCD_Transmit      = 0x04  # transmits data from the FIFO buffer
  PCD_NoCmdChange   = 0x07  # no command change, can be used to modify the CommandReg register bits without affecting the command, for example, the PowerDown bit
  PCD_Receive       = 0x08  # activates the receiver circuits
  PCD_Transceive    = 0x0C  # transmits data from FIFO buffer to antenna and automatically activates the receiver after transmission
  PCD_MFAuthent     = 0x0E  # performs the MIFARE standard authentication as a reader
  PCD_SoftReset     = 0x0F  # resets the MFRC522
  
  # PCD Command and Status Registers
  CommandReg        = 0x01  # starts and stops command execution
  ComIEnReg         = 0x02  # enable and disable interrupt request control bits
  DivIEnReg         = 0x03  # enable and disable interrupt request control bits
  ComIrqReg         = 0x04  # interrupt request bits
  DivIrqReg         = 0x05  # interrupt request bits
  ErrorReg          = 0x06  # error bits showing the error status of the last command executed 
  Status1Reg        = 0x07  # communication status bits
  Status2Reg        = 0x08  # receiver and transmitter status bits
  FIFODataReg       = 0x09  # input and output of 64 byte FIFO buffer
  FIFOLevelReg      = 0x0A  # number of bytes stored in the FIFO buffer
  WaterLevelReg     = 0x0B  # level for FIFO underflow and overflow warning
  ControlReg        = 0x0C  # miscellaneous control registers
  BitFramingReg     = 0x0D  # adjustments for bit-oriented frames
  CollReg           = 0x0E  # bit position of the first bit-collision detected on the RF interface
    
  # PCD Command Registers
  ModeReg           = 0x11  # defines general modes for transmitting and receiving 
  TxModeReg         = 0x12  # defines transmission data rate and framing
  RxModeReg         = 0x13  # defines reception data rate and framing
  TxControlReg      = 0x14  # controls the logical behavior of the antenna driver pins TX1 and TX2
  TxASKReg          = 0x15  # controls the setting of the transmission modulation
  TxSelReg          = 0x16  # selects the internal sources for the antenna driver
  RxSelReg          = 0x17  # selects internal receiver settings
  RxThresholdReg    = 0x18  # selects thresholds for the bit decoder
  DemodReg          = 0x19  # defines demodulator settings
  MfTxReg           = 0x1C  # controls some MIFARE communication transmit parameters
  MfRxReg           = 0x1D  # controls some MIFARE communication receive parameters
  SerialSpeedReg    = 0x1F  # selects the speed of the serial UART interface
    
  # PCD Configuration Registers
  CRCResultRegH     = 0x21  # shows the MSB and LSB values of the CRC calculation
  CRCResultRegL     = 0x22
  ModWidthReg       = 0x24  # controls the ModWidth setting?
  RFCfgReg          = 0x26  # configures the receiver gain
  GsNReg            = 0x27  # selects the conductance of the antenna driver pins TX1 and TX2 for modulation 
  CWGsPReg          = 0x28  # defines the conductance of the p-driver output during periods of no modulation
  ModGsPReg         = 0x29  # defines the conductance of the p-driver output during periods of modulation
  TModeReg          = 0x2A  # defines settings for the internal timer
  TPrescalerReg     = 0x2B  # the lower 8 bits of the TPrescaler value. The 4 high bits are in TModeReg.
  TReloadRegH       = 0x2C  # defines the 16-bit timer reload value
  TReloadRegL       = 0x2D
  TCounterValueRegH = 0x2E  # shows the 16-bit timer value
  TCounterValueRegL = 0x2F
    
  # PCD Test Registers
  TestSel1Reg       = 0x31  # general test signal configuration
  TestSel2Reg       = 0x32  # general test signal configuration
  TestPinEnReg      = 0x33  # enables pin output driver on pins D1 to D7
  TestPinValueReg   = 0x34  # defines the values for D1 to D7 when it is used as an I/O bus
  TestBusReg        = 0x35  # shows the status of the internal test bus
  AutoTestReg       = 0x36  # controls the digital self test
  VersionReg        = 0x37  # shows the software version
  AnalogTestReg     = 0x38  # controls the pins AUX1 and AUX2
  TestDAC1Reg       = 0x39  # defines the test value for TestDAC1
  TestDAC2Reg       = 0x3A  # defines the test value for TestDAC2
  TestADCReg        = 0x3B  # shows the value of ADC I and Q channels

  def initialize(nrstpd = 24, chip = 0, spd = 8000000, timer = 50)
    chip_option = { 0 => PiPiper::Spi::CHIP_SELECT_0,
                    1 => PiPiper::Spi::CHIP_SELECT_1,
                    2 => PiPiper::Spi::CHIP_SELECT_BOTH,
                    3 => PiPiper::Spi::CHIP_SELECT_NONE }
    @spi_chip = chip_option[chip]
    @spi_spd = spd

    # Power it up
    nrstpd_pin = PiPiper::Pin.new(pin: nrstpd, direction: :out)
    nrstpd_pin.on
    sleep 1.0 / 20.0 # Wait 50ms

    soft_reset # Perform software reset

    write_spi(TModeReg, 0x8D) # Start timer by setting TAuto=1, and higher part of TPrescalerReg
    write_spi(TPrescalerReg, 0x3E) # Set lower part of TPrescalerReg, and results in 2khz timer (f_timer = 13.56 MHz / (2*TPreScaler+1))
    write_spi(TReloadRegH, (timer >> 8))
    write_spi(TReloadRegL, (timer & 0xFF)) # 50 ticks @2khz defines 25ms per timer cycle
    
    write_spi(TxASKReg, 0x40) # Default 0x00. Force a 100 % ASK modulation independent of the ModGsPReg register setting
    write_spi(ModeReg, 0x3D) # Default 0x3F. Set the preset value for the CRC coprocessor for the CalcCRC command to 0x6363 (ISO 14443-3 part 6.2.4)

    antenna_on # Turn antenna on. They were disabled by the reset.
  end

  def soft_reset
    write_spi(CommandReg, PCD_SoftReset)
    sleep 1.0 / 20.0 # wait 50ms
  end

  def read_spi(reg)
    output = 0
    PiPiper::Spi.begin do |spi|
      spi.chip_select_active_low(true)
      spi.bit_order Spi::MSBFIRST
      spi.clock @spi_spd

      spi.chip_select(@spi_chip) do
        spi.write((reg << 1) & 0x7E | 0x80)
        output = spi.read
      end
    end
    output
  end

  def write_spi(reg, values)
    PiPiper::Spi.begin do |spi|
      spi.chip_select_active_low(true)
      spi.bit_order Spi::MSBFIRST
      spi.clock @spi_spd

      spi.chip_select(@spi_chip) do
        spi.write((reg << 1) & 0x7E, *values)
      end
    end
  end

  def write_spi_set_bitmask(reg, mask)
    value = read_spi(reg)
    write_spi(reg, value | mask)
  end

  def write_spi_clear_bitmask(reg, mask)
    value = read_spi(reg)
    write_spi(reg, value & (~mask))
  end

  def antenna_on
    value = read_spi(TxControlReg)
    write_spi_set_bitmask(TxControlReg, 0x03) if (value & 0x03) != 0x03
  end

  def antenna_off
    write_spi_clear_bitmask(TxControlReg, 0x03)
  end

  # level = 1: 18dB, 2: 23dB, 3: 33dB, 4: 38dB, 5: 43dB, 6: 48dB
  def antenna_gain(level = nil)
    unless level.nil?
      level = 1 if level > 6 || level < 1
      write_spi_set_bitmask(RFCfgReg, ((level + 1) << 4))
    end
    (read_spi(RFCfgReg) & 0x70) >> 4
  end

  def calculate_crc(send_data)
    write_spi(CommandReg, PCD_Idle)               # Stop any active command.
    write_spi(DivIrqReg, 0x04)                    # Clear the CRCIRq interrupt request bit
    write_spi_set_bitmask(FIFOLevelReg, 0x80)     # FlushBuffer = 1, FIFO initialization
    write_spi(FIFODataReg, send_data)             # Write data to the FIFO
    write_spi(CommandReg, PCD_CalcCRC)            # Start the calculation

    # Wait for the command to complete
    i = 5000
    loop do
      irq = read_spi(DivIrqReg)
      break if (irq & 0x04) != 0
      return :status_pcd_timeout if i == 0
      i -= 1
    end

    write_spi(CommandReg, PCD_Idle)               # Stop calculating CRC for new content in the FIFO.

    result = []
    result << read_spi(CRCResultRegL)
    result << read_spi(CRCResultRegH)
    
    return :status_ok, result
  end

  def communicate_with_picc(command, send_data, framing_bit = 0)
    status = :status_ok
    wait_irq = 0x00
    wait_irq = 0x10 if command == PCD_MFAuthent
    wait_irq = 0x30 if command == PCD_Transceive

    write_spi(CommandReg, PCD_Idle)               # Stop any active command.
    write_spi(ComIrqReg, 0x7F)                    # Clear all seven interrupt request bits
    write_spi_set_bitmask(FIFOLevelReg, 0x80)     # FlushBuffer = 1, FIFO initialization
    write_spi(FIFODataReg, send_data)             # Write sendData to the FIFO
    write_spi(BitFramingReg, framing_bit)         # Bit adjustments
    write_spi(CommandReg, command)                # Execute the command
    if command == PCD_Transceive
      write_spi_set_bitmask(BitFramingReg, 0x80)  # StartSend=1, transmission of data starts
    end

    # Wait for the command to complete
    i = 2000
    loop do
      irq = read_spi(ComIrqReg)
      break if (irq & wait_irq) != 0
      return :status_picc_timeout if (irq & 0x01) != 0
      return :status_pcd_timeout if i == 0
      i -= 1
    end

    # Check for error
    error = read_spi(ErrorReg)
    return :status_error if (error & 0x13) != 0 # BufferOvfl ParityErr ProtocolErr
    status = :status_collision if (error & 0x08) != 0 # CollErr

    # Receiving data
    received_data = []
    data_length = read_spi(FIFOLevelReg)
    while data_length > 0 do
      data = read_spi(FIFODataReg)
      received_data << data
      data_length -=1
    end
    valid_bits = read_spi(ControlReg) & 0x07

    return status, received_data, valid_bits
  end

  # Wakes PICC from HALT or IDLE to ACTIVE state
  def picc_request(picc_command) # Accept PICC_REQA and PICC_WUPA command
    write_spi_clear_bitmask(CollReg, 0x80)  # ValuesAfterColl=1 => Bits received after collision are cleared.

    status, _received_data, valid_bits = communicate_with_picc(PCD_Transceive, picc_command, 0x07)

    return status if status != :status_ok
    return :status_error if valid_bits != 0 # REQA or WUPA command return 16 bits(full byte)

    return :status_ok
  end

  # Instruct PICC in ACTIVE state go to HALT
  def picc_halt
    buffer = [PICC_HLTA, 0]

    # Calculate CRC and append it into buffer
    status, result = calculate_crc(buffer)
    return status if status != :status_ok
    buffer << result[0] << result[1]

    status, _received_data, _valid_bits = communicate_with_picc(PCD_Transceive, buffer)

    # PICC in HALT state will not respond
    # If PICC sent reply, means it didn't acknowledge the command we sent
    return :status_ok if status == :status_picc_timeout
    return :status_error if status == :status_ok

    return status
  end

  # PICC must be in state ACTIVE
  def picc_select
    #  Description of buffer structure:
    #
    #  Byte 0: SEL   Indicates the Cascade Level: PICC_CMD_SEL_CL1, PICC_CMD_SEL_CL2 or PICC_CMD_SEL_CL3
    #  Byte 1: NVB   Number of Valid Bits (in complete command, not just the UID): High nibble: complete bytes, Low nibble: Extra bits. 
    #  Byte 2: UID-data or Cascade Tag
    #  Byte 3: UID-data
    #  Byte 4: UID-data
    #  Byte 5: UID-data
    #  Byte 6: Block Check Character - XOR of bytes 2-5
    #  Byte 7: CRC_A
    #  Byte 8: CRC_A
    #  The BCC and CRC_A are only transmitted if we know all the UID bits of the current Cascade Level.
    #
    #  Description of bytes 2-5
    #
    #  UID size  Cascade level Byte2 Byte3 Byte4 Byte5
    #  ========  ============= ===== ===== ===== =====
    #   4 bytes        1       uid0  uid1  uid2  uid3
    #   7 bytes        1       CT    uid0  uid1  uid2
    #                  2       uid3  uid4  uid5  uid6
    #  10 bytes        1       CT    uid0  uid1  uid2
    #                  2       CT    uid3  uid4  uid5
    #                  3       uid6  uid7  uid8  uid9

    write_spi_clear_bitmask(CollReg, 0x80)    # ValuesAfterColl=1 => Bits received after collision are cleared.
    select_level = [PICC_SEL_CL1, PICC_SEL_CL2, PICC_SEL_CL3]
    uid = []

    for current_cascade_level in 0..2
      buffer = [select_level[current_cascade_level]]
      current_level_known_bits = 0

      loop do
        if current_level_known_bits >= 32 # Prepare to do a complete select if we knew everything
          tx_last_bits = 0
          buffer[1] = 0x70 # NVB - We're sending full length byte[0..6]
          buffer << (buffer[2] ^ buffer[3] ^ buffer[4] ^ buffer[5]) # Block Check Character

          # Append CRC to buffer
          status, crc = calculate_crc(buffer)
          return status if status != :status_ok
          buffer << crc[0] << crc[1]
        else
          tx_last_bits = current_level_known_bits % 8
          uid_full_byte = current_level_known_bits / 8
          all_full_byte = 2 + uid_full_byte # length of SEL + NVB + UID
          buffer[1] = (all_full_byte << 4) + tx_last_bits # NVB
        end

        framing_bit = (tx_last_bits << 4) + tx_last_bits

        # Try to fetch UID
        status, received_data, valid_bits = communicate_with_picc(PCD_Transceive, buffer, framing_bit)
        return status if status != :status_ok

        # Append received UID into buffer if not doing full select
        buffer = buffer[0...all_full_byte] + received_data if current_level_known_bits < 32

        # Handle collision
        if status == :status_collision
          collision = read_spi(CollReg)

          return :status_collision if (collision & 0x20) != 0 # CollPosNotValid - We don't know where collision happened
          collision_position = collision & 0x1F
          collision_position = 32 if collision_position == 0 # Values 0-31, 0 means bit 32
          return :status_internal_error if collision_position <= current_level_known_bits
        
          # Mark the bit
          current_level_known_bits = collision_position
          uid_bit = (current_level_known_bits - 1) % 8
          uid_byte = (current_level_known_bits / 8) + (uid_bit != 0 ? 1 : 0)
          buffer[1 + uid_byte] |= (1 << uid_bit)
        elsif status == :status_ok
          break if current_level_known_bits >= 32
          current_level_known_bits = 32 # We've already known all bits, loop again for a complete select
        else
          return status
        end 
      end

      # We've finished current cascade level
      # Check and collect all uid in this level

      # Append UID
      uid << buffer[2] if buffer[2] != PICC_CT
      uid << buffer[3] << buffer[4] << buffer[5]

      # Check the result of full select
      return :status_sak_error if received_data.count != 3 || valid_bits != 0 # Select Acknowledge is 1 byte + CRC_A

      status, crc = calculate_crc(received_data)
      return status if status != :status_ok
      return :status_crc_error if received_data[1] != crc[0] || received_data[2] != crc[1]

      sak = received_data[0]

      break if (received_data[0] & 0x04) == 0 # No more cascade level
    end

    return :status_ok, uid, sak
  end

  # PICC must be selected before calling for authenticate
  # You must deauthenticate after communication, or no new communication can be made
  def mifare_authenticate(uid)

  end

  def mifare_deauthenticate
    write_spi_clear_bitmask(Status2Reg, 0x08) # Clear MFCrypto1On bit
  end

  def mifare_read

  end

  def mifare_write

  end

  def mifare_ultralight_write

  end
end

