Gem::Specification.new do |s|
  s.name        = 'tamashii-mfrc522'
  s.version     = '1.0.8'
  s.date        = '2017-09-10'
  s.summary     = 'MFRC522 RFID Reader Library for RaspberryPi'
  s.authors     = ['atitan', 'Liang-Chi Tseng']
  s.email       = ['commit@atifans.net', 'lctseng@5xruby.tw']
  s.files       = Dir['lib/*.rb'] + Dir['lib/mifare/*.rb']
  s.homepage    = 'https://github.com/tamashii-io/MFRC522_Ruby'
  s.license     = 'MIT'
  s.add_runtime_dependency 'pi_piper', '~> 2.0.0', '>= 2.0.0'
end
