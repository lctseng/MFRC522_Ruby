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
    @pcd.reestablish_picc_communication(@uid)
  end

  def halt
    @pcd.picc_halt
  end
end
