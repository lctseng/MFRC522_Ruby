## MFRC522 1.0.1 ##

*   Rename `KEY_ENCRYPTION` to `KEY_COMMUNICATION` in `DESFire`

## MFRC522 1.0.0 ##

*   Use exception on error handling at higher level of abstraction.

*   Add support for Mifare DESFire EV1.

*   Add suuport for ISO 14443-4 protocol.

## MFRC522 0.2.0 ##

*   Introduce PICC abstraction.

*   Add support for Mifare Ultralight and Mifare Ultralight C.

*   Class name now comes all uppercased.

## Mfrc522 0.1.2 ##

*   Add addtional check on buffer while selecting card.

## Mfrc522 0.1.0 ##

*   Fixed critical bug in `picc_select`.

*   `mifare_authenticate` and `mifare_deauthenticate` renamed to
    `mifare_crypto1_authenticate` and `mifare_crypto1_deauthenticate` respectively.

## Mfrc522 0.0.1 ##

*   Initial release.
