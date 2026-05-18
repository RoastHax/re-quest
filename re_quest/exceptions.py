class ReQuestError(Exception):
    pass


class ProfileError(ReQuestError):
    pass


class BackendUnavailable(ReQuestError):
    pass


class TransportError(ReQuestError):
    pass


class RedirectError(ReQuestError):
    pass


class TooManyRedirects(RedirectError):
    pass
