from redflare.modules import (
    ApplicationMappingModule,
    HeaderModule,
    PassiveReconModule,
    PathDiscoveryModule,
    SensitiveExposureModule,
    SurfaceAnalysisModule,
)
from redflare.modules.adapters import GatekeeperAdapter, NoAuthAdapter


PROFILES = {
    "quick": [PassiveReconModule, HeaderModule, SensitiveExposureModule],
    "web": [PassiveReconModule, HeaderModule, SurfaceAnalysisModule, ApplicationMappingModule, PathDiscoveryModule, SensitiveExposureModule],
    "full": [PassiveReconModule, HeaderModule, SurfaceAnalysisModule, ApplicationMappingModule, PathDiscoveryModule, GatekeeperAdapter, NoAuthAdapter, SensitiveExposureModule],
}


def build_modules(profile: str):
    try:
        return [module() for module in PROFILES[profile]]
    except KeyError as exc:
        raise ValueError(f"unknown profile: {profile}") from exc
