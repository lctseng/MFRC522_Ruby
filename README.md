# MFRC522_Ruby

This is a Ruby port of [miguelbalboa/rfid](https://github.com/miguelbalboa/rfid) for Raspberry Pi.

##Installation
You can install it by doing `gem install mfrc522`.

##Documentation
RDoc is available at [RubyDoc](http://www.rubydoc.info/github/atitan/MFRC522_Ruby/master/Mfrc522).

##Get started
Simple demo code
```ruby
require 'mfrc522'

# NRSTPD(or RST) is the pin to power up the chip.
# Timer is the value of internal timer for timeout interrupt. 50 means 25ms.
# SPD unit is in bps(hertz), 8000000 = 8Mbps = 8Mhz
# chip_option = { 0 => PiPiper::Spi::CHIP_SELECT_0,
#                 1 => PiPiper::Spi::CHIP_SELECT_1,
#                 2 => PiPiper::Spi::CHIP_SELECT_BOTH,
#                 3 => PiPiper::Spi::CHIP_SELECT_NONE }
reader = Mfrc522.new(nrstpd = 24, chip = 0, spd = 8000000, timer = 50)

# Wakes the PICC
status = reader.picc_request(Mrfc522::PICC_REQA)

# Select PICC UID
status, uid, sak = reader.picc_select

# Check PICC type
puts "PICC type is #{picc_type(sak)}"

# Start encrypted communication
sector_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
block_addr = 0x08
status = reader.mifare_authenticate(Mrfc522::PICC_MF_AUTH_KEY_A, block_addr, sector_key, uid)

# Read something
status, data = reader.mifare_read(block_addr)

# Stop encrypted communication
reader.mifare_deauthenticate

# Halt the PICC
status = reader.picc_halt
```
