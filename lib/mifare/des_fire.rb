module Mifare
  class DESFire < ::ISO144434
    # Security Related Commands
    CMD_DES_AUTH                  = 0x1A # Authenticate with DES, 2K3DES, 3K3DES key
    CMD_AES_AUTH                  = 0xAA # Authenticate with AES-128 key
    CMD_GET_KEY_SETTING           = 0x45 # Gets information on the PICC and application master key settings. In addition it returns the maximum number of keys which can be stored within the selected application.
    CMD_CHANGE_KEY_SETTING        = 0x54 # Changes the master key settings on PICC and application level.
    CMD_GET_KEY_VERSION           = 0x64 # Reads out the current key version of any key stored on the PICC.
    CMD_CHANGE_KEY                = 0xC4 # Changes any key stored on the PICC.

    # PICC Level Commands
    CMD_CREATE_APP                = 0xCA # Creates new applications on the PICC.
    CMD_DELETE_APP                = 0xDA # Permanently deactivates applications on the PICC.
    CMD_GET_APP_IDS               = 0x6A # Returns the Application IDentifiers of all applications on a PICC.
    CMD_SELECT_APP                = 0x5A # Selects one specific application for further access.
    CND_GET_CARD_VERSION          = 0x60 # Returns manufacturing related data of the PICC.
    CMD_FORMAT_CARD               = 0xFC # Releases the PICC user memory.

    # Application Level Commands
    CMD_GET_FILE_IDS              = 0x6F # Returns the File IDentifiers of all active files within the currently selected application.
    CMD_GET_FILE_SETTING          = 0xF5 # Get information on the properties of a specific file.
    CMD_CHANGE_FILE_SETTING       = 0x5F # Changes the access parameters of an existing file.
    CMD_CREATE_STD_DATA_FILE      = 0xCD # Creates files for the storage of plain unformatted user data within an existing application on the PICC.
    CMD_CREATE_BACKUP_DATA_FILE   = 0xCB # Creates files for the storage of plain unformatted user data within an existing application on the PICC, additionally supporting the feature of an integrated backup mechanism.
    CMD_CREATE_VALUE_FILE         = 0xCC # Creates files for the storage and manipulation of 32bit signed integer values within an existing application on the PICC.
    CMD_CREATE_LINEAR_RECORD_FILE = 0xC1 # Creates files for multiple storage of structural similar data, for example for loyalty programs, within an existing application on the PICC. Once the file is filled completely with data records, further writing to the file is not possible unless it is cleared.
    CMD_CREATE_CYCLIC_RECORD_FILE = 0xC0 # Creates files for multiple storage of structural similar data within an existing application on the PICC. Once the file is filled completely with data records, the PICC automatically overwrites the oldest record with the latest written one.
    CMD_DELETE_FILE               = 0xDF # Permanently deactivates a file within the file directory of the currently selected application.

    # Data Manipulation Commands
    CMD_READ_DATA                 = 0xBD # Reads data from Standard Data Files or Backup Data Files.
    CMD_WRITE_DATA                = 0x3D # Writes data to Standard Data Files or Backup Data Files.
    CMD_GET_VALUE                 = 0x6C # Reads the currently stored value from Value Files.
    CMD_CREDIT                    = 0x0C # Increases a value stored in a Value File.
    CMD_DEBIT                     = 0xDC # Decreases a value stored in a Value File.
    CMD_LIMITED_CREDIT            = 0x1C # Allows a limited increase of a value stored in a Value File without having full Credit permissions to the file.
    CMD_WRITE_RECORD              = 0x3B # Writes data to a record in a Cyclic or Linear Record File.
    CMD_READ_RECORDS              = 0xBB # Reads out a set of complete records from a Cyclic or Linear Record File.
    CMD_CLEAR_RECORD_FILE         = 0xEB # Resets a Cyclic or Linear Record File to empty state.
    CMD_COMMIT_TRANSACTION        = 0xC7 # Validates all previous write access’ on Backup Data Files, Value Files and Record Files within one application.
    CMD_ABORT_TRANSACTION         = 0xA7 # Invalidates all previous write access’ on Backup Data Files, Value Files and Record Files within one application.


    KEY_TYPE = {'des-ede-cbc' => 0x00, 'des-ede3-cbc' => 0x40, 'aes-128-cbc' => 0x80}
    KEY_SETTING = {}

    def initialize(pcd, uid, sak)
      super
      invalid_auth
      @cmac_buffer = []
    end

    def deselect
      super
      invalid_auth
    end

    def transceive(cmd, send_data = [], calc_cmac = nil)
      raise UnexpectedDataError, 'Set calc_cmac when in Authed state' if calc_cmac.nil? && @authed

      buffer = [cmd] + send_data

      if (calc_cmac == :both || calc_cmac == :tx) && cmd != 0xAF && @authed
        @cmac_buffer = buffer
        cmac = @session_key.calculate_cmac(@cmac_buffer)
      end

      received_data = super(buffer)
      card_status = received_data.shift

      if card_status != 0x00 && card_status != 0xAF
        invalid_auth
      end

      if (calc_cmac == :both || calc_cmac == :rx) && (card_status == 0x00 || card_status == 0xAF) && @authed
        @cmac_buffer = [] if cmd != 0xAF
        @cmac_buffer.concat(received_data) if card_status == 0xAF

        if received_data.size >= 8 && card_status == 0x00
          received_cmac = received_data.pop(8)
          @cmac_buffer.concat(received_data + [card_status])
          cmac = @session_key.calculate_cmac(@cmac_buffer)
          if cmac != received_cmac
            raise MismatchCMACError
          end
        end
      end

      return card_status, received_data
    end

    def get_app_ids
      ids = []

      card_status, received_data = transceive(CMD_GET_APP_IDS, [], :both)
      ids.concat(received_data)

      # 20 applications or above will need two frames
      if card_status == 0xAF
        card_status, received_data = transceive(0xAF, [], :rx)
        ids.concat(received_data)
      end

      raise UnexpectedDataError, 'Incorrect response' if card_status != 0x00

      return ids if ids.size == 0

      ids = ids.each_slice(3).to_a
      ids.map do |id|
        (id[2] << 16) & (id[1] << 8) & id[0]
      end
    end

    def select_app(id)
      invalid_auth

      id = [(id >> 16) & 0xFF, (id >> 8) & 0xFF, id & 0xFF].reverse

      card_status, received_data = transceive(CMD_SELECT_APP, id)

      card_status == 0x00
    end

    def create_app(id, key_setting, key_count, cipher_suite)
      
    end

    def auth(key_number, auth_key)
      cmd = (auth_key.type == :des) ? CMD_DES_AUTH : CMD_AES_AUTH
      auth_key.clear_iv

      # Ask for authentication
      card_status, received_data = transceive(cmd, [key_number])
      raise UnexpectedDataError, 'Incorrect response' if card_status != 0xAF

      challenge = auth_key.decrypt(received_data)
      challenge_rot = challenge.rotate

      # Generate 8 bytes random number and encrypt it with rotated challenge
      random_number = SecureRandom.random_bytes(8).bytes
      response = auth_key.encrypt(random_number + challenge_rot)

      # Send challenge response
      card_status, received_data = transceive(0xAF, response)
      raise UnexpectedDataError, 'Incorrect response' if card_status != 0x00

      # Check if verification matches rotated random_number
      verification = auth_key.decrypt(received_data)

      if random_number.rotate != verification
        halt
        return @authed = false
      end

      # Generate session key
      session_key = random_number[0..3] + challenge[0..3]

      if auth_key.key_size > 8
        if auth_key.cipher_suite == 'des-ede-cbc'
          session_key.concat(random_number[4..7] + challenge[4..7])
        elsif auth_key.cipher_suite == 'des-ede3-cbc'
          session_key.concat(random_number[6..9] + challenge[6..9])
          session_key.concat(random_number[12..15] + challenge[12..15])
        elsif auth_key.cipher_suite == 'aes-128-cbc'
          session_key.concat(random_number[12..15] + challenge[12..15])
        end
      end

      @session_key = Key.new(auth_key.type, session_key, key_number)
      @session_key.generate_cmac_subkeys
      @authed = true
    end

    private

    def invalid_auth
      @authed = false
      @session_key = nil
    end
  end
end
