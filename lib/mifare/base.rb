module Mifare
  class Base

    attr_reader :uid
    attr_reader :sak

    def initialize(pcd, uid, sak)
      @pcd = pcd
      @uid = uid
      @sak = sak
    end

    def re
      
    end

    def halt
      @pcd.picc_halt  
    end

  end
end