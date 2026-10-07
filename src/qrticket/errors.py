class QRTicketError(Exception):
    pass


class TicketFormatError(QRTicketError):
    pass


class PayloadFormatError(QRTicketError):
    pass


class QRReadError(QRTicketError):
    pass
