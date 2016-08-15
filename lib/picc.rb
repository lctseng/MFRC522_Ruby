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
    @pcd.reestablish_picc_communication(@uid) && @halted = false
  end

  def halt
    @pcd.picc_halt && @halted = true
  end
end
