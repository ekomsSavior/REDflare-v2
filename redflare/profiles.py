from redflare.modules import HeaderModule, PassiveReconModule, PathDiscoveryModule, SurfaceAnalysisModule
from redflare.modules.adapters import GatekeeperAdapter, NoAuthAdapter


PROFILES = {
    "quick": [PassiveReconModule, HeaderModule],
    "web": [PassiveReconModule, HeaderModule, SurfaceAnalysisModule, PathDiscoveryModule],
    "full": [PassiveReconModule, HeaderModule, SurfaceAnalysisModule, PathDiscoveryModule, GatekeeperAdapter, NoAuthAdapter],
}


def build_modules(profile: str):
    try:
        return [module() for module in PROFILES[profile]]
    except KeyError as exc:
        raise ValueError(f"unknown profile: {profile}") from exc
