require 'mfrc522'

r = MFRC522.new

r.picc_request(MFRC522::PICC_REQA)

uid, sak = r.picc_select

c = Mifare::Classic.new(r, uid, sak)

