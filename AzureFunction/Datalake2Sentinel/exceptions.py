class DatalakeError(Exception):
    pass

class DatalakeConnectionError(DatalakeError):
    pass

class DatalakeAuthenticationError(DatalakeError):
    pass

class DatalakePermissionError(DatalakeError):
    pass