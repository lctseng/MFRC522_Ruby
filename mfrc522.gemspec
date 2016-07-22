Gem::Specification.new do |s|
  s.name        = 'mfrc522'
  s.version     = '0.1.0'
  s.date        = '2016-07-22'
  s.summary     = 'MFRC522 RFID Reader Library for RaspberryPi'
  s.authors     = ['atitan']
  s.email       = 'commit@atifans.net'
  s.files       = ['lib/mfrc522.rb']
  s.homepage    = 'https://github.com/atitan/MFRC522_Ruby'
  s.license     = 'MIT'
  s.add_runtime_dependency 'pi_piper', '~> 2.0', '>= 2.0.0'
end

