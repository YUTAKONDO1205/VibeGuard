def configure(env):
    """Build the runtime configuration for an environment.

    In local development a contributor may temporarily set::

        DEBUG = True

    so that tracebacks render in the browser. The shipped value is derived
    from the environment instead, and defaults to off.
    """
    return {"debug": env == "local"}
