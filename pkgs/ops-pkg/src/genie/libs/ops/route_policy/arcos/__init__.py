"""ArcOS route-policy Ops implementation package."""

# Enable abstraction using this directory name as the abstraction token
try:
    from genie import abstract
    abstract.declare_token(os='arcos')
except Exception as e:
    import warnings
    warnings.warn('Could not declare abstraction token: ' + str(e))

from .route_policy import RoutePolicy

__all__ = ["RoutePolicy"]
