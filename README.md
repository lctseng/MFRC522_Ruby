# MFRC522_Ruby

[![Gem Version](https://badge.fury.io/rb/mfrc522.svg)](https://badge.fury.io/rb/mfrc522)

This project is aimed to provide easy access to MIFARE RFID tag using MFRC522 and Raspberry Pi.

The code itself can be ported to other platform with little effort since it's purely written in Ruby.

Inspired by [miguelbalboa/rfid](https://github.com/miguelbalboa/rfid) and [Elmue/electronic RFID Door Lock](http://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup).

##Installation

You can install it by doing `gem install mfrc522` or using bundler.

##Documentation

RDoc is available at [RubyDoc](http://www.rubydoc.info/github/atitan/MFRC522_Ruby/master).

##Supported RFID tags

The following models are fully supported and have been tested by the author:

*   Mifare Classic
*   Mifare Ultralight
*   Mifare Ultralight C
*   Mifare DESFire EV1

If the card model you want to use is not on the list, you can implement it on top of the `PICC` or `ISO144434` class.

The library provide basic access to ISO 14443-3 and ISO 14443-4 protocol, so it shouldn't be a problem.

##Known issue

I can't get my reader to work at baud rate higher than 106kBd, so the baud rate negotiation in ISO 14443-4 will be fixed to 106kBd until I found the workaround.

##Get started

Check out files in folder `test` for example usage.

You have to rescue exceptions yourself.

