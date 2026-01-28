# === plugin_utils.py ===

#Utility decorators and helpers for BYO-SecAI plugin metadata

def supported_iocs(*types: str):
    """
    Decorator to declare which IOC types a plugin `run` function supports.
    Usage:
        @supported_iocs('ip', 'hash')
        def run(ioc: str): ...
    """
    def decorator(fn):
        setattr(fn, 'supported_iocs', set(types))
        return fn
    return decorator