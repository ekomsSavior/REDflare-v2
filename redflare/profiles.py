from redflare.modules import (
    ApplicationMappingModule,
    HeaderModule,
    PassiveReconModule,
    PathDiscoveryModule,
    SensitiveExposureModule,
    SurfaceAnalysisModule,
    CVEIntelligenceModule,
    NativeBrowserRuntimeModule,
    NativeNoAuthModule,
    NetworkDiscoveryModule,
)


PROFILES = {
    "quick": [PassiveReconModule, HeaderModule, CVEIntelligenceModule, SensitiveExposureModule],
    "web": [PassiveReconModule, HeaderModule, SurfaceAnalysisModule, ApplicationMappingModule, PathDiscoveryModule, CVEIntelligenceModule, SensitiveExposureModule],
    "full": [NetworkDiscoveryModule, PassiveReconModule, HeaderModule, SurfaceAnalysisModule, ApplicationMappingModule, PathDiscoveryModule, NativeBrowserRuntimeModule, NativeNoAuthModule, CVEIntelligenceModule, SensitiveExposureModule],
}


def build_modules(profile: str):
    try:
        return [module() for module in PROFILES[profile]]
    except KeyError as exc:
        raise ValueError(f"unknown profile: {profile}") from exc
