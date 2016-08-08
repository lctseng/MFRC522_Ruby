# MFRC522_Ruby

[![Gem Version](https://badge.fury.io/rb/mfrc522.svg)](https://badge.fury.io/rb/mfrc522)

This is a Ruby port of [miguelbalboa/rfid](https://github.com/miguelbalboa/rfid) for Raspberry Pi.

##Installation
You can install it by doing `gem install mfrc522`.

##Documentation
RDoc is available at [RubyDoc](http://www.rubydoc.info/github/atitan/MFRC522_Ruby/master/Mfrc522).

##Project Status
Author has confirmed that it works with Mifare Classic and Mifare Ultralight series.

Support for Mifare Ultralight C 3DES authentication since gem version 0.2.0.

Mifare DESFire and Mifare Plus is not currently usable.

`mifare_authenticate` and `mifare_deauthenticate` method name has been renamed since gem version 0.1.0.

##Get started

Mifare Classic Demo Code

```ruby
require 'mfrc522'

# NRSTPD(or RST) is the pin to power up the chip.
# Timer is the value of internal timer for timeout interrupt. 50 means 25ms.
# SPD unit is in bps(hertz), 8000000 = 8Mbps = 8Mhz
# chip_option = { 0 => PiPiper::Spi::CHIP_SELECT_0,
#                 1 => PiPiper::Spi::CHIP_SELECT_1,
#                 2 => PiPiper::Spi::CHIP_SELECT_BOTH,
#                 3 => PiPiper::Spi::CHIP_SELECT_NONE }
reader = MFRC522.new(nrstpd = 24, chip = 0, spd = 8000000, timer = 50)

# Wakes the PICC
status = reader.picc_request(MFRC522::PICC_REQA)

# Select PICC UID
status, uid, sak = reader.picc_select

# Check PICC type
puts "PICC type is #{reader.identify_model(sak)}"

# Create card abstraction
card = Mifare::Classic.new(reader, uid, sak)

# Authenticate block 0x08 with Key A
status = card.auth(0x08, a: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

# Read from 0x08 and 0x09 (same sector only need to auth once)
status, data = card.read(0x08)
status, data = card.read(0x09)

# Write an integer value to 0x0A
status = card.write_value(0x09, 13500)

# Deauthenticate
card.deauth

# Halt the PICC
status = card.halt
```

Mifare Ultralight Demo Code

```ruby
require 'mfrc522'

# Using default value
reader = MFRC522.new

# Wakes the PICC
status = reader.picc_request(MFRC522::PICC_REQA)

# Select PICC UID
status, uid, sak = reader.picc_select

# Check PICC type
puts "PICC type is #{reader.identify_model(sak)}"

# Create card abstraction
card = Mifare::Ultralight.new(reader, uid, sak)

# Check whether Ultralight C or not
if card.is_c?
  # Write 3DES keys
  status = card.write_des_key('49454D4B41455242214E4143554F5946')

  # Restart the PICC then authenticate to see if it worked
  status = card.resume_communication
  status = card.auth('49454D4B41455242214E4143554F5946')

  # Enable read-write protection from page 0x10
  status = card.set_protection_type(0)
  status = card.enable_protection_from(0x10)
end

# Read 16 bytes from 0x03
status, data = card.read(0x03)

# Write 4 bytes to 0x06
status = card.write(0x06, [0x12, 0x34, 0x56, 0x78])

# Halt the PICC
status = card.halt
```
