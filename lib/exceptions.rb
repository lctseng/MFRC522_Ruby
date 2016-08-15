class TimeoutError < StandardError; end

class CommunicationError < StandardError; end
class PICCTimeoutError < CommunicationError; end
class PCDTimeoutError < CommunicationError; end
class IncorrectCRCError < CommunicationError; end
class CollisionError < CommunicationError; end

class UnexpectedDataError < StandardError; end

class MifareNakError < StandardError; end