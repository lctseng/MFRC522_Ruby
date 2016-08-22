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
    CMD_GET_CARD_VERSION          = 0x60 # Returns manufacturing related data of the PICC.
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

    # Status code returned by DESFire
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

    KEY_SETTING = Struct.new(
      # Key number(0x00~0x0D) required for `change_key`
      # 0x0E means same key, 0x0F freezes all keys
      :privileged_key,
      # Set if master key can be modified
      :mk_changeable,
      # Set if listing requires master key
      :listing_without_mk,
      # Set if create or delete requires master key
      :create_delete_without_mk,
      # Set if this setting can be modified
      :configuration_changeable) do
      def initialize(*data)
        super
        default
      end

      def default
        self[:privileged_key] = 0 unless privileged_key
        self[:mk_changeable] = true unless mk_changeable
        self[:listing_without_mk] = true unless listing_without_mk
        self[:create_delete_without_mk] = true unless create_delete_without_mk
        self[:configuration_changeable] = true unless configuration_changeable
      end

      def import(byte)
        self[:privileged_key] = (byte >> 4) & 0x0F
        self[:mk_changeable] = byte & 0x01 != 0
        self[:listing_without_mk] = (byte >> 1) & 0x01 != 0
        self[:create_delete_without_mk] = (byte >> 2) & 0x01 != 0
        self[:configuration_changeable] = (byte >> 3) & 0x01 != 0
        self
      end

      def to_uint
        output = (privileged_key << 4)
        output |= 0x01 if mk_changeable
        output |= 0x02 if listing_without_mk
        output |= 0x04 if create_delete_without_mk
        output |= 0x08 if configuration_changeable
        output
      end
    end

    FILE_TYPE = {
      std_data_file: 0x00, backup_data_file: 0x01, value_file: 0x02,
      linear_record_file: 0x03, cyclic_record_file: 0x04
    }

    FILE_ENCRYPTION = {plain: 0x00, mac: 0x01, encrypt: 0x03}

    # value 0x00 ~ 0x0D are key numbers, 0x0E grants free access, 0x0F always denies access
    FILE_PERMISSION = Struct.new(:read_access, :write_access, :read_write_access, :change_access) do
      def to_uint
        (read_access << 12) | (write_access << 8) | (read_write_access << 4) | change_access
      end
    end

    FILE_SETTING = Struct.new(
      :type,
      :encryption,
      :permissions,
      # Data file only
      :size, # PICC will allocate n * 32 bytes memory internally
      # Value file only
      :lower_limit,
      :upper_limit,
      :limited_credit_value,
      :limited_credit,
      # Record file only
      :record_size,
      :max_record_number,
      :current_record_number
    )

    CARD_VERSION = Struct.new(
      :hw_vendor, :hw_type, :hw_subtype, :hw_major_ver, :hw_minor_ver, :hw_storage_size, :hw_protocol,
      :sw_vendor, :sw_type, :sw_subtype, :sw_major_ver, :sw_minor_ver, :sw_storage_size, :sw_protocol,
      :uid, :batch_number, :production_week, :production_year
    )

    attr_reader :selected_app

    def initialize(pcd, uid, sak)
      super
      invalid_auth
      @cmac_buffer = []
      @selected_app = false
    end

    def authed?
      @authed.is_a? Numeric
    end

    def deselect
      super
      invalid_auth
    end

    def transceive(cmd: , plain_data: [], data: [], tx: nil, rx: nil, expect: nil)
      if (tx == :encrypt || rx == :encrypt) && !@authed
        raise UnauthenticatedError
      end

      plain_data = [plain_data] unless plain_data.is_a? Array
      data = [data] unless data.is_a? Array

      buffer = [cmd] + plain_data

      if tx == :encrypt
        data.append_uint(crc32(buffer, data), 4)
        data = @session_key.encrypt(data)
      end

      buffer.concat(data)

      if tx == :cmac && cmd != CMD_ADDITIONAL_FRAME && @authed
        @cmac_buffer = buffer
        cmac = @session_key.calculate_cmac(@cmac_buffer)
      end

      received_data = super(buffer)
      card_status = received_data.shift

      if card_status != ST_SUCCESS && card_status != ST_ADDITIONAL_FRAME
        invalid_auth
      end

      error_msg = check_status_code(card_status)

      unless error_msg.empty?
        raise ReceivedStatusError, "0x#{card_status.to_s(16).rjust(2, '0').upcase} - #{error_msg}"
      end

      if expect && expect != card_status
        raise UnexpectedDataError, 'Card status does not match expected value'
      end

      if rx == :cmac && (card_status == ST_SUCCESS || card_status == ST_ADDITIONAL_FRAME) && @authed
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

      if rx == :encrypt
        received_data = @session_key.decrypt(received_data)
      end

      if expect
        return received_data
      else
        return card_status, received_data
      end
    end

    def auth(key_number, auth_key)
      cmd = (auth_key.type == :des) ? CMD_DES_AUTH : CMD_AES_AUTH
      auth_key.clear_iv

      # Ask for authentication
      received_data = transceive(cmd: cmd, data: key_number, expect: ST_ADDITIONAL_FRAME)

      challenge = auth_key.decrypt(received_data)
      challenge_rot = challenge.rotate

      # Generate random number and encrypt it with rotated challenge
      random_number = SecureRandom.random_bytes(received_data.size).bytes
      response = auth_key.encrypt(random_number + challenge_rot)

      # Send challenge response
      received_data = transceive(cmd: CMD_ADDITIONAL_FRAME, data: response, expect: ST_SUCCESS)

      # Check if verification matches rotated random_number
      verification = auth_key.decrypt(received_data)

      if random_number.rotate != verification
        halt
        @authed = false

        raise UnexpectedDataError, 'Authentication Failed'
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
      @authed = key_number

      authed?
    end

    def get_app_ids
      ids = []

      card_status, received_data = transceive(cmd: CMD_GET_APP_IDS, tx: :cmac, rx: :cmac)
      ids.concat(received_data)

      # 20 applications or above will need two frames
      if card_status == ST_ADDITIONAL_FRAME
        card_status, received_data = transceive(cmd: CMD_ADDITIONAL_FRAME, rx: :cmac)
        ids.concat(received_data)
      end

      raise UnexpectedDataError, 'Incorrect response' if card_status != ST_SUCCESS

      return ids if ids.size == 0

      ids = ids.each_slice(3).to_a
      ids.map do |id|
        id.to_uint
      end
    end

    def app_exist?(id)
      get_app_ids.include?(id)
    end

    def select_app(id)
      invalid_auth

      transceive(cmd: CMD_SELECT_APP, data: convert_app_id(id), expect: ST_SUCCESS)

      @selected_app = id
    end

    def create_app(id, key_setting, key_count, cipher_suite)
      raise UnauthenticatedError unless @authed
      raise UnexpectedDataError, 'An application can only hold up to 14 keys.' if key_count > 14

      buffer = convert_app_id(id) + [key_setting.to_uint, key_count | KEY_TYPE[cipher_suite]]

      transceive(cmd: CMD_CREATE_APP, data: buffer, tx: :cmac, rx: :cmac, expect: ST_SUCCESS)
    end

    def delete_app(id)
      raise UnauthenticatedError unless @authed

      transceive(cmd: CMD_DELETE_APP, data: convert_app_id(id), tx: :cmac, rx: :cmac, expect: ST_SUCCESS)
    end

    def get_card_version
      version = []

      received_data = transceive(cmd: CMD_GET_CARD_VERSION, tx: :cmac, rx: :cmac, expect: ST_ADDITIONAL_FRAME)
      version.concat(received_data)

      received_data = transceive(cmd: CMD_ADDITIONAL_FRAME, rx: :cmac, expect: ST_ADDITIONAL_FRAME)
      version.concat(received_data)

      received_data = transceive(cmd: CMD_ADDITIONAL_FRAME, rx: :cmac, expect: ST_SUCCESS)
      version.concat(received_data)

      CARD_VERSION.new(
        version[0], version[1], version[2], version[3], version[4], 1 << (version[5] / 2), version[6],
        version[7], version[8], version[9], version[10], version[11], 1 << (version[12] / 2), version[13],
        version[14..20], version[21..25], version[26].to_s(16).to_i, 2000 + version[27].to_s(16).to_i
      )
    end

    def format_card
      raise UnauthenticatedError unless @authed

      transceive(cmd: CMD_FORMAT_CARD, tx: :cmac, rx: :cmac, expect: ST_SUCCESS)
    end

    def get_key_version(key_number)
      received_data = transceive(cmd: CMD_GET_KEY_VERSION, data: key_number, tx: :cmac, rx: :cmac, expect: ST_SUCCESS)

      received_data[0]
    end

    def change_key(key_number, new_key, curr_key)
      raise UnauthenticatedError unless @authed
      raise UnexpectedDataError, 'Invalid key number' if key_number > 13
      
      cryptogram = new_key.key

      same_key = (key_number == @authed)

      # Only Master Key can change its key type
      key_number |= KEY_TYPE[new_key.cipher_suite] if @selected_app == 0

      # XOR new key if we're using different one
      unless same_key
        cryptogram = cryptogram.zip(curr_key.key).map{|x, y| x ^ y }
      end

      # AES stores key version separately
      if new_key.type == :aes
        cryptogram.append_uint(new_key.version, 1)
      end

      cryptogram.append_uint(crc32([CMD_CHANGE_KEY, key_number], cryptogram), 4)

      unless same_key
        cryptogram.append_uint(crc32(new_key.key), 4)
      end

      # Encrypt cryptogram
      buffer = [key_number] + @session_key.encrypt(cryptogram)

      # Change current used key will revoke authentication
      invalid_auth if same_key

      transceive(cmd: CMD_CHANGE_KEY, data: buffer, rx: :cmac, expect: ST_SUCCESS)
    end

    def get_key_setting
      received_data = transceive(cmd: CMD_GET_KEY_SETTING, tx: :cmac, rx: :cmac, expect: ST_SUCCESS)

      { key_setting: KEY_SETTING.new.import(received_data[0]),
        key_count: received_data[1] & 0x0F,
        key_type: KEY_TYPE.key(received_data[1] & 0xF0) }
    end

    def change_key_setting(key_setting)
      raise UnauthenticatedError unless @authed

      transceive(cmd: CMD_CHANGE_KEY_SETTING, data: key_setting.to_uint, tx: :encrypt, rx: :cmac, expect: ST_SUCCESS)
    end

    def get_file_ids
      transceive(cmd: CMD_GET_FILE_IDS, tx: :cmac, rx: :cmac, expect: ST_SUCCESS)
    end

    def get_file_setting(id)
      received_data = transceive(cmd: CMD_GET_FILE_SETTING, data: id, tx: :cmac, rx: :cmac, expect: ST_SUCCESS)

      file_setting = FILE_SETTING.new
      file_setting[:type] = received_data.shift
      file_setting[:encryption] = received_data.shift
      file_setting[:permissions] = received_data.shift(2).to_uint

      case FILE_TYPE.key(file_setting.file_type)
      when :std_data_file, :backup_data_file
        file_setting[:size] = received_data.shift(3).to_uint
      when :value_file
        file_setting[:lower_limit] = received_data.shift(4).to_uint
        file_setting[:upper_limit] = received_data.shift(4).to_uint
        file_setting[:limited_credit_value] = received_data.shift(4).to_uint
        file_setting[:limited_credit] = received_data.shift == 0x01
      when :linear_record_file, :cyclic_record_file
        file_setting[:record_size] = received_data.shift(3).to_uint
        file_setting[:max_record_number] = received_data.shift(3).to_uint
        file_setting[:current_record_number] = received_data.shift(3).to_uint
      end

      file_setting
    end

    def create_std_data_file(id, file_setting)
      buffer = [id]
      buffer.append_uint(file_setting.encryption, 1)
      buffer.append_uint(file_setting.permissions, 2)
      buffer.append_uint(file_setting.size, 3)

      transceive(cmd: CMD_CREATE_STD_DATA_FILE, data: buffer, tx: :cmac, rx: :cmac, expect: ST_SUCCESS)
    end

    def delete_file(id)
      transceive(cmd: CMD_DELETE_FILE, data: id, tx: :cmac, rx: :cmac, expect: ST_SUCCESS)
    end

    def read_data_file(id, offset, length)
      buffer = [id]
      card_status, received_data = transceive(cmd: CMD_READ_DATA, data: buffer, tx: :cmac, rx: :cmac)
    end

    def write_data_file(id, offset, data)
      
    end

    private

    def invalid_auth
      @authed = false
      @session_key = nil
      @cmac_buffer = []
    end

    def convert_app_id(id)
      raise UnexpectedDataError, 'Application ID overflow' if id < 0 || id >= (1 << 24)

      [].append_uint(id, 3)
    end

    def crc32(*datas)
      crc = 0xFFFFFFFF

      datas.each do |data|
        data = [data] unless data.is_a? Array
        data.each do |byte|
          crc ^= byte
          8.times do
            flag = crc & 0x01 > 0
            crc >>= 1
            crc ^= 0xEDB88320 if flag
          end
        end
      end
      crc
    end

    def check_status_code(code)
      case code
      when ST_SUCCESS, ST_NO_CHANGES, ST_ADDITIONAL_FRAME
        ''
      when ST_OUT_OF_MEMORY
        'Insufficient NV-Memory to complete command.'
      when ST_ILLEGAL_COMMAND
        'Command code not supported.'
      when ST_INTEGRITY_ERROR
        'CRC or MAC does not match data. Padding bytes not valid.'
      when ST_KEY_NOT_EXIST
        'Invalid key number specified.'
      when ST_WRONG_COMMAND_LEN
        'Length of command string invalid.'
      when ST_PERMISSION_DENIED
        'Current configuration / status does not allow the requested command.'
      when ST_INCORRECT_PARAM
        'Value of the parameter(s) invalid.'
      when ST_APP_NOT_FOUND
        'Requested AID not present on PICC.'
      when ST_APPL_INTEGRITY_ERROR
        'Unrecoverable error within application, application will be disabled.'
      when ST_AUTHENTICATION_ERROR
        'Authentication error or insufficient privilege.'
      when ST_BOUNDARY_ERROR
        'Attempt to read/write data from/to beyond the file\'s/record\'s limits.'
      when ST_PICC_INTEGRITY_ERROR
        'Unrecoverable error within PICC, PICC will be disabled.'
      when ST_COMMAND_ABORTED
        'Previous Command was not fully completed. Not all Frames were requested or provided by the PCD.'
      when ST_PICC_DISABLED_ERROR
        'PICC was disabled by an unrecoverable error.'
      when ST_COUNT_ERROR
        'Number of Applications limited to 28, no additional CreateApplication possible.'
      when ST_DUPLICATE_ERROR
        'Creation of file/application failed because file/application with same number already exists.'
      when ST_EEPROM_ERROR
        'Could not complete NV-write operation due to loss of power, internal backup/rollback mechanism activated.'
      when ST_FILE_NOT_FOUND
        'Specified file number does not exist.'
      when ST_FILE_INTEGRITY_ERROR
        'Unrecoverable error within file, file will be disabled.'
      else
        'Unknown Error Code.'
      end
    end
  end
end
