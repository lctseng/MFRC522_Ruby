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

    ST_SUCCESS                    = 0x00
    ST_NO_CHANGES                 = 0x0C
    ST_OUT_OF_MEMORY              = 0x0E
    ST_ILLEGAL_COMMAND            = 0x1C
    ST_INTEGRITY_ERROR            = 0x1E
    ST_KEY_NOT_EXIST              = 0x40
    ST_WRONG_COMMAND_LEN          = 0x7E
    ST_PERMISSION_DENIED          = 0x9D
    ST_INCORRECT_PARAM            = 0x9E
    ST_APP_NOT_FOUND              = 0xA0
    ST_APPL_INTEGRITY_ERROR       = 0xA1
    ST_AUTHENTICATION_ERROR       = 0xAE
    ST_ADDITIONAL_FRAME           = 0xAF
    ST_BOUNDARY_ERROR             = 0xBE
    ST_PICC_INTEGRITY_ERROR       = 0xC1
    ST_COMMAND_ABORTED            = 0xCA
    ST_PICC_DISABLED_ERROR        = 0xCD
    ST_COUNT_ERROR                = 0xCE
    ST_DUPLICATE_ERROR            = 0xDE
    ST_EEPROM_ERROR               = 0xEE
    ST_FILE_NOT_FOUND             = 0xF0
    ST_FILE_INTEGRITY_ERROR       = 0xF1

    KEY_TYPE = {'des-ede-cbc' => 0x00, 'des-ede3-cbc' => 0x40, 'aes-128-cbc' => 0x80}
    KEY_SETTING = {
      # If this bit is set, the MK can be changed, otherwise it is frozen.
      ALLOW_CHANGE_MK:              0x01,
      # Picc key: If this bit is set, GetApplicationIDs, GetKeySettings do not require MK authentication.
      # App  key: If this bit is set, GetFileIDs, GetFileSettings, GetKeySettings do not require MK authentication.
      LISTING_WITHOUT_MK:           0x02,
      # Picc key: If this bit is set, CreateApplication does not require MK authentication.
      # App  key: If this bit is set, CreateFile, DeleteFile do not require MK authentication.
      CREATE_DELETE_WITHOUT_MK:     0x04,
      # If this bit is set, the configuration settings of the MK can be changed, otherwise they are frozen.
      CONFIGURATION_CHANGEABLE:     0x08,
      # Set every bits listed above.
      FACTORY_DEFAULT:              0x0F,

      CHANGE_KEY_WITH_MK:           0x00, # A key change requires MK authentication
      CHANGE_KEY_WITH_KEY_1:        0x10, # A key change requires authentication with key 1
      CHANGE_KEY_WITH_KEY_2:        0x20, # A key change requires authentication with key 2
      CHANGE_KEY_WITH_KEY_3:        0x30, # A key change requires authentication with key 3
      CHANGE_KEY_WITH_KEY_4:        0x40, # A key change requires authentication with key 4
      CHANGE_KEY_WITH_KEY_5:        0x50, # A key change requires authentication with key 5
      CHANGE_KEY_WITH_KEY_6:        0x60, # A key change requires authentication with key 6
      CHANGE_KEY_WITH_KEY_7:        0x70, # A key change requires authentication with key 7
      CHANGE_KEY_WITH_KEY_8:        0x80, # A key change requires authentication with key 8
      CHANGE_KEY_WITH_KEY_9:        0x90, # A key change requires authentication with key 9
      CHANGE_KEY_WITH_KEY_A:        0xA0, # A key change requires authentication with key 10
      CHANGE_KEY_WITH_KEY_B:        0xB0, # A key change requires authentication with key 11
      CHANGE_KEY_WITH_KEY_C:        0xC0, # A key change requires authentication with key 12
      CHANGE_KEY_WITH_KEY_D:        0xD0, # A key change requires authentication with key 13
      CHANGE_KEY_WITH_TARGETED_KEY: 0xE0, # A key change requires authentication with the same key that is to be changed
      CHANGE_KEY_FROZEN:            0xF0  # All keys are frozen
    }

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
      raise UnexpectedDataError, 'Implicit calc_cmac in Authed state is not supported' if calc_cmac.nil? && @authed

      buffer = [cmd] + send_data

      if (calc_cmac == :both || calc_cmac == :tx) && cmd != CMD_ADDITIONAL_FRAME && @authed
        @cmac_buffer = buffer
        cmac = @session_key.calculate_cmac(@cmac_buffer)
      end

      received_data = super(buffer)
      card_status = received_data.shift

      if card_status != ST_SUCCESS && card_status != ST_ADDITIONAL_FRAME
        invalid_auth
      end

      if (calc_cmac == :both || calc_cmac == :rx) && (card_status == ST_SUCCESS || card_status == ST_ADDITIONAL_FRAME) && @authed
        @cmac_buffer = [] if cmd != CMD_ADDITIONAL_FRAME
        @cmac_buffer.concat(received_data) if card_status == ST_ADDITIONAL_FRAME

        if received_data.size >= 8 && card_status == ST_SUCCESS
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

    def auth(key_number, auth_key)
      cmd = (auth_key.type == :des) ? CMD_DES_AUTH : CMD_AES_AUTH
      auth_key.clear_iv

      # Ask for authentication
      card_status, received_data = transceive(cmd, [key_number])
      raise UnexpectedDataError, 'Incorrect response' if card_status != ST_ADDITIONAL_FRAME

      challenge = auth_key.decrypt(received_data)
      challenge_rot = challenge.rotate

      # Generate 8 bytes random number and encrypt it with rotated challenge
      random_number = SecureRandom.random_bytes(8).bytes
      response = auth_key.encrypt(random_number + challenge_rot)

      # Send challenge response
      card_status, received_data = transceive(CMD_ADDITIONAL_FRAME, response)
      raise UnexpectedDataError, 'Incorrect response' if card_status != ST_SUCCESS

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

      @session_key = Key.new(auth_key.type, session_key)
      @session_key.generate_cmac_subkeys
      @authed = true
    end

    def get_app_ids
      ids = []

      card_status, received_data = transceive(CMD_GET_APP_IDS, [], :both)
      ids.concat(received_data)

      # 20 applications or above will need two frames
      if card_status == ST_ADDITIONAL_FRAME
        card_status, received_data = transceive(CMD_ADDITIONAL_FRAME, [], :rx)
        ids.concat(received_data)
      end

      raise UnexpectedDataError, 'Incorrect response' if card_status != ST_SUCCESS

      return ids if ids.size == 0

      ids = ids.each_slice(3).to_a
      ids.map do |id|
        convert_app_id(id)
      end
    end

    def app_exist?(id)
      get_app_ids.include?(id)
    end

    def select_app(id)
      invalid_auth

      card_status, received_data = transceive(CMD_SELECT_APP, convert_app_id(id))

      card_status == ST_SUCCESS
    end

    def create_app(id, key_setting, key_count, cipher_suite)
      raise UnauthenticatedError unless @authed
      raise UnexpectedDataError, 'Too many keys' if key_count > 14

      buffer = convert_app_id(id) + [key_setting, key_count | KEY_TYPE[cipher_suite]]

      card_status, received_data = transceive(CMD_CREATE_APP, buffer, :both)

      card_status == ST_SUCCESS
    end

    def delete_app(id)
      raise UnauthenticatedError unless @authed

      card_status, received_data = transceive(CMD_DELETE_APP, convert_app_id(id), :both)

      card_status == ST_SUCCESS
    end

    def get_key_version(key_number)
      card_status, received_data = transceive(CMD_GET_KEY_VERSION, key_number, :both)

      raise UnexpectedDataError, 'Incorrect response' if card_status != ST_SUCCESS

      received_data
    end

    def change_key(key_number, new_key)
      raise UnauthenticatedError unless @authed
      
    end

    def get_key_setting()
      
    end

    def change_key_setting()
      raise UnauthenticatedError unless @authed
      
    end

    private

    def invalid_auth
      @authed = false
      @session_key = nil
    end

    def convert_app_id(id)
      if id.is_a?(Array)
        raise UnexpectedDataError, 'Application ID overflow' if id.size > 3

        (id[2] << 16) & (id[1] << 8) & id[0]
      else
        raise UnexpectedDataError, 'Application ID overflow' if id < 0 || id >= (1 << 24)

        [(id >> 16) & 0xFF, (id >> 8) & 0xFF, id & 0xFF].reverse
      end
    end
  end
end
