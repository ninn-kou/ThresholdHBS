from enum import Enum

from threshold_hbs.models import SystemParameters
from threshold_hbs.signatures.lamport import LamportSignatureScheme
from threshold_hbs.signatures.winternitz import WinternitzSignatureScheme


class SignatureSchemeEnum(Enum):
    WINTERNITZ = "Winternitz"
    LAMPORT = "Lamport"


def make_params(
    num_parties: int = 5,
    num_leaves: int = 8,
    threshold_k: int = 3,
    digest_size_bytes: int = 32,
    lamport_element_size_bytes: int = 32,
    signature_scheme: SignatureSchemeEnum = SignatureSchemeEnum.WINTERNITZ,
    batching: int = 3
) -> SystemParameters:

    if signature_scheme == SignatureSchemeEnum.WINTERNITZ:
        scheme = WinternitzSignatureScheme(
            digest_size_bytes,
            lamport_element_size_bytes,
            4
        )
    else:
        scheme = LamportSignatureScheme(
            digest_size_bytes,
            lamport_element_size_bytes
        )

    return SystemParameters(
        num_parties=num_parties,
        num_leaves=num_leaves,
        threshold_k=threshold_k,
        digest_size_bytes=digest_size_bytes,
        lamport_element_size_bytes=lamport_element_size_bytes,
        signature_scheme=scheme,
        batching=batching
    )