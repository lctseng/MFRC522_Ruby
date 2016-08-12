# MFRC522_Ruby

[![Gem Version](https://badge.fury.io/rb/mfrc522.svg)](https://badge.fury.io/rb/mfrc522)

This project is aimed to provide easy access to MIFARE RFID tag using MFRC522 and Raspberry Pi.

The code itself can be ported to other platform with little effort since it's purely written in Ruby.

Inspired by [miguelbalboa/rfid](https://github.com/miguelbalboa/rfid) and [Elmue/electronic RFID Door Lock](http://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup).

##Installation
You can install it by doing `gem install mfrc522` or using bundler.

##Documentation
RDoc is available at [RubyDoc](http://www.rubydoc.info/github/atitan/MFRC522_Ruby/master/Mfrc522).

##Project Status
Author has confirmed that it works with Mifare Classic, Mifare Ultralight, and Mifare Ultralight C.

Support for Mifare Ultralight C 3DES authentication since gem version 0.2.0.

Mifare DESFire and Mifare Plus is not currently usable.

##Get started

Currently it's not safe to use this library since API changes very often.