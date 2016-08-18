class CommunicationError < StandardError; end
class PICCTimeoutError < CommunicationError; end
class PCDTimeoutError < CommunicationError; end
class IncorrectCRCError < CommunicationError; end
class CollisionError < CommunicationError; end

class UnexpectedDataError < StandardError; end

class ReceivedStatusError < StandardError; end

class MismatchCMACError < StandardError; end

class MifareNakError < StandardError; end

class UnauthenticatedError < StandardError; end