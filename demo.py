from __future__ import annotations

from threshold_hbs import (
    SystemParameters,
    aggregator_sign,
    dealer_setup,
    verify_threshold_signature,
)


def main() -> None:
    params = SystemParameters(
        num_parties=4,
        num_leaves=8,
        digest_size_bytes=8,
        lamport_element_size_bytes=16,
    )

    dealer_output = dealer_setup(params, ["P1", "P2", "P3", "P4"])

    message = b"hello threshold HBS"
    key_id = 0

    signature = aggregator_sign(message, key_id, dealer_output, None, params)

    ok = verify_threshold_signature(
        message,
        signature,
        dealer_output.composite_public_key,
        params,
    )
    tampered_ok = verify_threshold_signature(
        b"hello threshold HBS?",
        signature,
        dealer_output.composite_public_key,
        params,
    )

    print("key_id:", signature.key_id)
    print("randomizer_len:", len(signature.randomizer))
    print("auth_path_len:", len(signature.auth_path))
    print("lamport_values:", len(signature.lamport_signature_values))
    print("verified(original):", ok)
    print("verified(tampered):", tampered_ok)


if __name__ == "__main__":
    main()
