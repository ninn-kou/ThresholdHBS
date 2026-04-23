class SigningRefusedError(RuntimeError):
    pass


class KeyReuseError(SigningRefusedError):
    pass