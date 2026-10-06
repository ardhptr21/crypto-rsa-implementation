class RSAError(Exception):
    pass


class KeyGenerationError(RSAError):
    pass


class EncodingError(RSAError):
    pass


class DecryptionError(RSAError):
    pass
