from redflare.modules import (
    ApplicationMappingModule,
    HeaderModule,
    PassiveReconModule,
    PathDiscoveryModule,
    SensitiveExposureModule,
    SurfaceAnalysisModule,
    CVEIntelligenceModule,
)
from redflare.modules.adapters import GatekeeperAdapter, NoAuthAdapter


PROFILES = {
    "quick": [PassiveReconModule, HeaderModule, CVEIntelligenceModule, SensitiveExposureModule],
    "web": [PassiveReconModule, HeaderModule, SurfaceAnalysisModule, ApplicationMappingModule, PathDiscoveryModule, CVEIntelligenceModule, SensitiveExposureModule],
    "full": [PassiveReconModule, HeaderModule, SurfaceAnalysisModule, ApplicationMappingModule, PathDiscoveryModule, GatekeeperAdapter, NoAuthAdapter, CVEIntelligenceModule, SensitiveExposureModule],
}


def build_modules(profile: str):
    try:
        return [module() for module in PROFILES[profile]]
    except KeyError as exc:
        raise ValueError(f"unknown profile: {profile}") from exc
