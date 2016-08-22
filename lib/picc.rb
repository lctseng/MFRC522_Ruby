class PICC
  attr_reader :uid
  attr_reader :sak

  def initialize(pcd, uid, sak)
    @pcd = pcd
    @uid = uid
    @sak = sak
    @halted = false
  end

  def resume_communication
    if @pcd.reestablish_picc_communication(@uid)
      @halted = false
      true
    else
      false
    end
  end

  def halt
    if @pcd.picc_halt
      @halted = true
    else
      @halted = false
    end
  end
end
