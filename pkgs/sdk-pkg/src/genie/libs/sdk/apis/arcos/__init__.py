"""ArcOS SDK APIs package.

Enable abstraction using this directory name as the abstraction token.
"""

try:
    from genie import abstract

    abstract.declare_token(os="arcos")
except Exception as e:  # pragma: no cover - defensive
    import warnings

    warnings.warn("Could not declare abstraction token: " + str(e))

