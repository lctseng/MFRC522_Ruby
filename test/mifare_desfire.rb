require 'mfrc522'
require 'securerandom'

r = MFRC522.new

r.picc_request(MFRC522::PICC_REQA)
uid, sak = r.picc_select

c = Mifare::DESFire.new(r, uid, sak)
c.select

picc_mk = Mifare::Key.new(:des, '0000000000000000')

des_default_key = Mifare::Key.new(:des, '0000000000000000')
des2k_default_key = Mifare::Key.new(:des, '00000000000000000000000000000000')
des3k_default_key = Mifare::Key.new(:des, '000000000000000000000000000000000000000000000000')
aes_default_key = Mifare::Key.new(:aes, '00000000000000000000000000000000')

default_key_setting = Mifare::DESFire::KEY_SETTING.new

APP1_ID = 3000
APP2_ID = 30000
APP3_ID = 300000
APP4_ID = 16000000

app1_key0 = Mifare::Key.new(:des, SecureRandom.hex(8))
app1_key0_1 = Mifare::Key.new(:des, SecureRandom.hex(8))
app1_key1 = Mifare::Key.new(:des, SecureRandom.hex(8))
app2_key0 = Mifare::Key.new(:des, SecureRandom.hex(16))
app2_key0_1 = Mifare::Key.new(:des, SecureRandom.hex(16))
app3_key0 = Mifare::Key.new(:des, SecureRandom.hex(24))
app3_key0_1 = Mifare::Key.new(:des, SecureRandom.hex(24))
app4_key0 = Mifare::Key.new(:aes, SecureRandom.hex(16))
app4_key0_1 = Mifare::Key.new(:aes, SecureRandom.hex(16))
app4_key1 = Mifare::Key.new(:aes, SecureRandom.hex(16))

c.select_app(0)
puts 'Selected App:0 OK'

c.auth(0, picc_mk)
puts 'Authed with key:0 OK'

c.format_card
puts 'Format card memory OK'

puts "Get_Card_Version: #{c.get_card_version}"

c.create_app(999, Mifare::DESFire::KEY_SETTING.new, 1, 'des-ede-cbc')
puts 'Created test app:999 for deleting test OK'

c.get_app_ids.each do |id|
  c.delete_app(id)
  puts "Deleted existing app:#{id} OK"
end

# App 1
c.create_app(APP1_ID, default_key_setting, 2, des_default_key.cipher_suite)
puts "Created app:#{APP1_ID} OK"

# App 2
c.create_app(APP2_ID, default_key_setting, 2, des2k_default_key.cipher_suite)
puts "Created app:#{APP2_ID} OK"

# App 3
c.create_app(APP3_ID, default_key_setting, 2, des3k_default_key.cipher_suite)
puts "Created app:#{APP3_ID} OK"

# App 4
c.create_app(APP4_ID, default_key_setting, 2, aes_default_key.cipher_suite)
puts "Created app:#{APP4_ID} OK"

if c.get_app_ids.size == 4
  puts '4 Apps created OK'
else
  raise 'App count incorrect'
end

## Key test
## App 1
c.select_app(APP1_ID)
puts "@@@@@Selected App1 OK@@@@@"

c.auth(0, des_default_key)
puts "Authed with key:0 OK"

if c.get_key_version(0) == 0
  puts 'Get key version OK'
else
  raise 'Unmatched key version'
end

app_key_setting = c.get_key_setting

if app_key_setting[:key_setting] == default_key_setting &&
   app_key_setting[:key_count] == 2 &&
   app_key_setting[:key_type] == des_default_key.cipher_suite
  puts 'Get key setting OK'
else
  raise 'Unmatched key setting'
end

key_setting = app_key_setting[:key_setting]
key_setting[:create_delete_without_mk] = false
puts 'Remove create_delete_without_mk from key setting'

c.change_key_setting(key_setting)
puts 'Change key setting OK'

app_key_setting = c.get_key_setting

if app_key_setting[:key_setting] == key_setting &&
   app_key_setting[:key_count] == 2 &&
   app_key_setting[:key_type] == des_default_key.cipher_suite
  puts 'Get key setting again OK'
else
  raise 'Unmatched key setting'
end

c.change_key(0, app1_key0, des_default_key)
puts 'Change key from default to app1_key0 OK'

c.auth(0, app1_key0)
puts 'Re-auth OK'

c.change_key(0, app1_key0_1, app1_key0)
puts 'Change key from app1_key0 to app1_key0_1 OK'

c.auth(0, app1_key0_1)
puts 'Re-auth OK'

c.change_key(1, app1_key1, des_default_key)
puts 'Change key 1 using key 0 OK'

c.auth(1, app1_key1)
puts 'Authenticate using key 1 OK'

## App 2
c.select_app(APP2_ID)
puts "@@@@@Selected App2 OK@@@@@"

c.auth(0, des2k_default_key)
puts "Authed with key:0 OK"

c.change_key(0, app2_key0, des2k_default_key)
puts 'Change key from default to app2_key0 OK'

c.auth(0, app2_key0)
puts 'Re-auth OK'

c.change_key(0, app2_key0_1, app2_key0)
puts 'Change key from app2_key0 to app2_key0_1 OK'

c.auth(0, app2_key0_1)
puts 'Re-auth OK'

## App 3
c.select_app(APP3_ID)
puts "@@@@@Selected App3 OK@@@@@"

c.auth(0, des3k_default_key)
puts "Authed with key:0 OK"

c.change_key(0, app3_key0, des3k_default_key)
puts 'Change key from default to app3_key0 OK'

c.auth(0, app3_key0)
puts 'Re-auth OK'

c.change_key(0, app3_key0_1, app3_key0)
puts 'Change key from app3_key0 to app3_key0_1 OK'

c.auth(0, app3_key0_1)
puts 'Re-auth OK'

## App 4
c.select_app(APP4_ID)
puts "@@@@@Selected App4 OK@@@@@"

c.auth(0, aes_default_key)
puts "Authed with key:0 OK"

c.change_key(0, app4_key0, aes_default_key)
puts 'Change key from default to app4_key0 OK'

c.auth(0, app4_key0)
puts 'Re-auth OK'

c.change_key(0, app4_key0_1, app4_key0)
puts 'Change key from app4_key0 to app4_key0_1 OK'

c.auth(0, app4_key0_1)
puts 'Re-auth OK'

c.change_key(1, app4_key1, aes_default_key)
puts 'Change key 1 using key 0 OK'

c.auth(1, app4_key1)
puts 'Authenticate using key 1 OK'

## Finish test
c.select_app(0)
puts 'Selected App:0 OK'

c.auth(0, picc_mk)
puts 'Authed with key:0 OK'

c.format_card
puts 'Format card memory OK'

if c.get_app_ids.empty?
  puts 'Apps has been purged OK'
else
  raise 'App still exists after formatting'
end