# MFRC522_Ruby

This is a Ruby port of [miguelbalboa/rfid](https://github.com/miguelbalboa/rfid) for Raspberry Pi.

##Installation
You can install it by doing `gem install mfrc522`.

##Documentation
RDoc is available at [RubyDoc](http://www.rubydoc.info/atitan/MFRC522_Ruby/master/Mfrc522).

##Get started
Simple demo code
```ruby
# NRSTPD(or RST) is the pin to power up the chip.
# Timer is the value of internal timer for timeout interrupt. 50 means 25ms.
reader = Mfrc522.new(nrstpd = 24, chip = 0, spd = 8000000, timer = 50)

# Wakes the PICC
status = reader.picc_request(Mrfc522::PICC_REQA)

# Select PICC UID
status, uid, sak = reader.picc_select

# Check PICC type
puts "PICC type is #{picc_type(sak)}"

# Start encrypted communication
status = reader.mifare_authenticate(Mrfc522::PICC_MF_AUTH_KEY_A, block_addr = 0x08, sector_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], uid)

# Read something
status, data = reader.mifare_read(block_addr = 0x08)

# Stop encrypted communication
reader.mifare_deauthenticate

# Halt the PICC
status = reader.picc_halt
```
