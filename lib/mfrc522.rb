require 'pi_piper'

require 'openssl_cmac'

require 'picc'
require 'iso144434'
require 'mifare/key'
require 'mifare/classic'
require 'mifare/ultralight'
require 'mifare/ultralight_c'
require 'mifare/des_fire'
require 'mifare/plus'

include PiPiper

class MFRC522

  # PICC commands used by the PCD to manage communication with several PICCs (ISO 14443-3, Type A, section 6.4)
  PICC_REQA         = 0x26  # REQuest command, Type A. Invites PICCs in state IDLE to go to READY and prepare for anticollision or selection. 7 bit frame.
  PICC_WUPA         = 0x52  # Wake-UP command, Type A. Invites PICCs in state IDLE and HALT to go to READY(*) and prepare for anticollision or selection. 7 bit frame.
  PICC_CT           = 0x88  # Cascade Tag. Not really a command, but used during anti collision.
  PICC_SEL_CL1      = 0x93  # Anti collision/Select, Cascade Level 1
  PICC_SEL_CL2      = 0x95  # Anti collision/Select, Cascade Level 2
  PICC_SEL_CL3      = 0x97  # Anti collision/Select, Cascade Level 3
  PICC_HLTA         = 0x50  # HaLT command, Type A. Instructs an ACTIVE PICC to go to state HALT.
  # Mifare Acknowledge
  PICC_MF_ACK       = 0x0A

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

  # Constructor
  def initialize(nrstpd = 24, chip = 0, spd = 8000000, timer = 256)
    chip_option = { 0 => PiPiper::Spi::CHIP_SELECT_0,
                    1 => PiPiper::Spi::CHIP_SELECT_1,
                    2 => PiPiper::Spi::CHIP_SELECT_BOTH,
                    3 => PiPiper::Spi::CHIP_SELECT_NONE }
    @spi_chip = chip_option[chip]
    @spi_spd = spd
    @timer = timer

    # Power it up
    nrstpd_pin = PiPiper::Pin.new(pin: nrstpd, direction: :out)
    nrstpd_pin.on
    sleep 1.0 / 20.0 # Wait 50ms

    soft_reset # Perform software reset

    write_spi(TModeReg, 0x87) # Start timer by setting TAuto=1, and higher part of TPrescalerReg
    write_spi(TPrescalerReg, 0xFF) # Set lower part of TPrescalerReg, and results in 302us timer (f_timer = 13.56 MHz / (2*TPreScaler+1))
    
    write_spi(TxASKReg, 0x40) # Default 0x00. Force a 100 % ASK modulation independent of the ModGsPReg register setting
    write_spi(ModeReg, 0x3D) # Default 0x3F. Set the preset value for the CRC coprocessor for the CalcCRC command to 0x6363 (ISO 14443-3 part 6.2.4)

    pcd_config_reset # default 256 ticks on 302us timer defines 77.33ms per timer cycle

    antenna_on # Turn antenna on. They were disabled by the reset.
  end

  # PCD software reset
  def soft_reset
    write_spi(CommandReg, PCD_SoftReset)
    sleep 1.0 / 20.0 # wait 50ms
  end

  # Reset PCD config to default
  def pcd_config_reset
    # Clear ValuesAfterColl bit
    write_spi_clear_bitmask(CollReg, 0x80)
    # Reset picc baud rate to 106 kBd
    write_spi(TxModeReg, 0x00)
    write_spi(RxModeReg, 0x00)
    # Set timer to default value
    internal_timer(@timer)
  end

  # Set PCD timer value for 302us default timer
  def internal_timer(timer = nil)
    if timer
      write_spi(TReloadRegH, (timer >> 8) & 0xFF)
      write_spi(TReloadRegL, (timer & 0xFF))
    end
    (read_spi(TReloadRegH) << 8) | read_spi(TReloadRegL)
  end

  # Read from SPI communication
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

  # Write to SPI communication
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

  # Helper for setting bits by mask
  def write_spi_set_bitmask(reg, mask)
    value = read_spi(reg)
    write_spi(reg, value | mask)
  end

  # Helper for clearing bits by mask
  def write_spi_clear_bitmask(reg, mask)
    value = read_spi(reg)
    write_spi(reg, value & (~mask))
  end

  # Turn antenna on
  def antenna_on
    write_spi_set_bitmask(TxControlReg, 0x03)
  end

  # Turn antenna off
  def antenna_off
    write_spi_clear_bitmask(TxControlReg, 0x03)
  end

  # Modify and show antenna gain level
  # level = 1: 18dB, 2: 23dB, 3: 33dB, 4: 38dB, 5: 43dB, 6: 48dB
  def antenna_gain(level = nil)
    unless level.nil?
      level = 1 if level > 6 || level < 1
      write_spi_set_bitmask(RFCfgReg, ((level + 1) << 4))
    end
    (read_spi(RFCfgReg) & 0x70) >> 4
  end

  # Calculate CRC using MFRC522's built-in coprocessor
  def calculate_crc(data)
    write_spi(CommandReg, PCD_Idle)               # Stop any active command.
    write_spi(DivIrqReg, 0x04)                    # Clear the CRCIRq interrupt request bit
    write_spi_set_bitmask(FIFOLevelReg, 0x80)     # FlushBuffer = 1, FIFO initialization
    write_spi(FIFODataReg, data)                  # Write data to the FIFO
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

  # Calculate and append CRC to data
  def append_crc(data)
    status, crc = calculate_crc(data)
    return status if status != :status_ok
    data << crc[0] << crc[1]

    return :status_ok, data
  end

  # Check CRC using MFRC522's built-in coprocessor
  def check_crc(data)
    status, crc = calculate_crc(data[0..-3])
    return status if status != :status_ok
    return :status_crc_error if data[-2] != crc[0] || data[-1] != crc[1]

    return :status_ok
  end

  # PCD transceive helper
  def communicate_with_picc(command, send_data, framing_bit = 0, check_crc = false)
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

    # Receiving data
    received_data = []
    data_length = read_spi(FIFOLevelReg)
    while data_length > 0 do
      data = read_spi(FIFODataReg)
      received_data << data
      data_length -=1
    end
    valid_bits = read_spi(ControlReg) & 0x07

    # Check CRC if requested
    if !received_data.empty? && check_crc
      return :status_mifare_nack if received_data.count == 1 && valid_bits == 4
      return :status_crc_error if received_data.count < 2 || valid_bits != 0

      status = check_crc(received_data)
      return status if status != :status_ok
    end

    status = :status_ok
    status = :status_collision if (error & 0x08) != 0 # CollErr

    return status, received_data, valid_bits
  end

  # Wakes PICC from HALT or IDLE to ACTIVE state
  #
  # Accept PICC_REQA and PICC_WUPA command
  def picc_request(picc_command)
    pcd_config_reset

    status, _received_data, valid_bits = communicate_with_picc(PCD_Transceive, picc_command, 0x07)

    return status if status != :status_ok
    return :status_unknown_data if valid_bits != 0 # REQA or WUPA command return 16 bits(full byte)

    return :status_ok
  end

  # Instruct PICC in ACTIVE state go to HALT state
  def picc_halt
    buffer = [PICC_HLTA, 0]

    # Calculate CRC and append it into buffer
    status, buffer = append_crc(buffer)
    return status if status != :status_ok

    status, _received_data, _valid_bits = communicate_with_picc(PCD_Transceive, buffer)

    # PICC in HALT state will not respond
    # If PICC sent reply, means it didn't acknowledge the command we sent
    return :status_ok if status == :status_picc_timeout
    return :status_error if status == :status_ok

    return status
  end

  # Select PICC for further communication
  #
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
    pcd_config_reset

    select_level = [PICC_SEL_CL1, PICC_SEL_CL2, PICC_SEL_CL3]
    uid = []

    for current_cascade_level in 0..2
      buffer = [select_level[current_cascade_level]]
      current_level_known_bits = 0
      received_data = []
      valid_bits = 0

      loop do
        if current_level_known_bits >= 32 # Prepare to do a complete select if we knew everything
          # ensure there's nothing weird in buffer
          if buffer.size != 6 && !buffer.select{|b| !buffer.is_a?(Fixnum)}.empty?
            current_level_known_bits = 0
            buffer = []
            next
          end

          tx_last_bits = 0
          buffer[1] = 0x70 # NVB - We're sending full length byte[0..6]
          buffer << (buffer[2] ^ buffer[3] ^ buffer[4] ^ buffer[5]) # Block Check Character

          # Append CRC to buffer
          status, buffer = append_crc(buffer)
          return status if status != :status_ok
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
        buffer = buffer[0...all_full_byte] + received_data[0..3] if current_level_known_bits < 32

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

      status = check_crc(received_data)
      return status if status != :status_ok

      sak = received_data[0]

      break if (received_data[0] & 0x04) == 0 # No more cascade level
    end

    return :status_ok, uid, sak
  end

  # Trying to wake it up again
  def reestablish_picc_communication(uid)
    status = picc_halt
    return status if status != :status_ok

    status = picc_request(PICC_WUPA)
    return status if status != :status_ok

    status, new_uid, new_sak = picc_select
    return status if status != :status_ok

    if uid == new_uid
      return :status_ok
    else
      return :status_different_card_detected
    end
  end

  # Lookup error message
  def error_type(error)
    case error
    when :status_ok
      'It worked'
    when :status_pcd_timeout
      'Reader did not responding'
    when :status_picc_timeout
      'Tag did not responding'
    when :status_crc_error
      'CRC check failed'
    when :status_mifare_nack
      'Tag sent negative acknowledge'
    when :status_collision
      'Multiple tags detected'
    when :status_unknown_data
      'Incorrect data received'
    when :status_internal_error
      'Something went wrong but it shouldnt happen'
    when :status_sak_error
      'Incorrect select acknowledge'
    when :status_auth_failed
      'Authentication failed'
    when :status_data_length_error
      'Incorrect input data length'
    when :status_incorrect_input
      'Incorrect input'
    when :status_different_card_detected
      'Different card detected while reselecting'
    when :status_error
      'Something went wrong'
    else
      'Unknown error type'
    end
  end

  # Lookup PICC name using sak
  def identify_model(sak)
    # SAK coding separation reference:
    # http://cache.nxp.com/documents/application_note/AN10833.pdf
    # http://www.nxp.com/documents/application_note/130830.pdf
    if sak & 0x04 != 0
      return :picc_uid_not_complete
    end

    if sak & 0x02 != 0
      return :picc_reserved_future_use
    end

    if sak & 0x08 != 0
      if sak & 0x10 != 0
        return :picc_mifare_4k
      end

      if sak & 0x01 != 0
        return :picc_mifare_mini
      end
      
      return :picc_mifare_1k
    end

    if sak & 0x10 != 0
      if sak & 0x01 != 0
        return :picc_mifare_plus_4k_sl2
      end
        
      return :picc_mifare_plus_2k_sl2
    end

    if sak == 0x00
      return :picc_mifare_ultralight
    end

    if sak & 0x20 != 0
      return :picc_iso_14443_4
    end

    if sak & 0x40 != 0
      return :picc_iso_18092
    end

    return :picc_unknown
  end

  # Start encrypted Crypto1 communication between reader and Mifare PICC
  #
  # PICC must be selected before calling for authentication
  # Remember to deauthenticate after communication, or no new communication can be made
  #
  # Accept PICC_MF_AUTH_KEY_A or PICC_MF_AUTH_KEY_B command
  # Checks datasheets for block address numbering of your PICC
  #
  def mifare_crypto1_authenticate(command, block_addr, sector_key, uid)
    #
    # Buffer[12]: {command, block_addr, sector_key[6], uid[4]}
    #
    buffer = [command, block_addr]
    buffer += sector_key[0..5]
    buffer += uid[0..3]

    status, _received_data, _valid_bits = communicate_with_picc(PCD_MFAuthent, buffer)

    return status if status != :status_ok
    return :status_auth_failed if (read_spi(Status2Reg) & 0x08) == 0

    return :status_ok
  end

  # Stop Mifare encrypted communication
  def mifare_crypto1_deauthenticate
    write_spi_clear_bitmask(Status2Reg, 0x08) # Clear MFCrypto1On bit
  end

  # Helper that append CRC to buffer and check CRC or Mifare acknowledge
  def picc_transceive(send_data, accept_timeout = false)
    # Append CRC
    status, send_data = append_crc(send_data)
    return status if status != :status_ok

    puts "Sending Data: #{send_data.map{|x|x.to_s(16).rjust(2,'0').upcase}}"

    # Transfer data
    status, received_data, valid_bits = communicate_with_picc(PCD_Transceive, send_data)
    return :status_ok if status == :status_picc_timeout && accept_timeout
    return status if status != :status_ok

    puts "Received Data: #{received_data.map{|x|x.to_s(16).rjust(2,'0').upcase}}"

    # Data exists, check CRC and return
    if received_data.size > 1
      return :status_crc_error if received_data.size < 3 || valid_bits != 0

      status = check_crc(received_data)
      return status, received_data[0..-3]
    end

    # Data doesn't exist, check mifare acknowledge
    return :status_error if received_data.size != 1 || valid_bits != 4 # ACK is 4 bits long
    return :status_mifare_nack, received_data[0] if received_data[0] != PICC_MF_ACK

    return :status_ok
  end

end
