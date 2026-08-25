class SessionNotFoundError(KeyError):
    pass


class SessionConflictError(ValueError):
    pass
