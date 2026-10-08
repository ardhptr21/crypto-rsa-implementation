from pathlib import Path

from crypto import RSAPrivateKey, sign_pss

from .payload import encode_payload
from .ticket import Ticket


def issue_ticket(ticket: Ticket, private_key: RSAPrivateKey) -> str:
    if not isinstance(ticket, Ticket):
        raise TypeError("ticket must be a Ticket")
    ticket_bytes = ticket.to_bytes()
    signature = sign_pss(ticket_bytes, private_key)
    return encode_payload(ticket_bytes, signature)


def issue_ticket_qr(
    ticket: Ticket,
    private_key: RSAPrivateKey,
    path: str | Path,
    **render_options,
) -> str:
    from .qr import render_qr

    payload = issue_ticket(ticket, private_key)
    render_qr(payload, path, **render_options)
    return payload
