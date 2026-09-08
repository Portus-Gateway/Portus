// Package conformance runs the Gateway API conformance test suite against
// the Portus Gateway implementation.
package conformance

import (
	"os"
	"testing"
	"time"

	"sigs.k8s.io/gateway-api/conformance"
	confv1 "sigs.k8s.io/gateway-api/conformance/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func TestConformance(t *testing.T) {
	opts := conformance.DefaultOptions(t)

	// Gateway class name matching our controller
	opts.GatewayClassName = "portus-gateway"

	// Every conformance profile Gateway API v1.6 defines.
	profiles := []suite.ConformanceProfileName{
		suite.GatewayHTTPConformanceProfileName,
		suite.GatewayTLSConformanceProfileName,
		suite.GatewayGRPCConformanceProfileName,
		suite.GatewayTCPConformanceProfileName,
		suite.GatewayUDPConformanceProfileName,
	}

	// Declare supported features. Core features (SupportGateway, SupportHTTPRoute)
	// must be listed explicitly when using SupportedFeatures, otherwise the suite
	// skips core tests. Extended features enable additional test coverage.
	opts.SupportedFeatures = []features.FeatureName{
		// Core
		features.SupportGateway,
		features.SupportGatewayHTTPListenerIsolation,
		features.SupportGatewayInfrastructurePropagation,
		features.SupportGatewayAddressEmpty,
		features.SupportGatewayHTTPSListenerDetectMisdirectedRequests,
		features.SupportListenerSet,
		features.SupportHTTPRoute,
		features.SupportReferenceGrant,
		// Extended: redirect status codes
		features.SupportHTTPRoute303RedirectStatusCode,
		features.SupportHTTPRoute307RedirectStatusCode,
		features.SupportHTTPRoute308RedirectStatusCode,
		// Extended: matching
		features.SupportHTTPRouteMethodMatching,
		features.SupportHTTPRouteQueryParamMatching,
		features.SupportHTTPRouteDestinationPortMatching,
		features.SupportHTTPRouteParentRefPort,
		// Extended: filters
		features.SupportHTTPRouteRequestMirror,
		features.SupportHTTPRouteRequestMultipleMirrors,
		features.SupportHTTPRouteRequestPercentageMirror,
		features.SupportHTTPRouteRequestTimeout,
		features.SupportHTTPRouteBackendTimeout,
		features.SupportHTTPRouteHostRewrite,
		features.SupportHTTPRoutePathRedirect,
		features.SupportHTTPRoutePathRewrite,
		features.SupportHTTPRoutePortRedirect,
		features.SupportHTTPRouteSchemeRedirect,
		features.SupportHTTPRouteResponseHeaderModification,
		features.SupportHTTPRouteBackendRequestHeaderModification,
		// Extended: named rules
		features.SupportHTTPRouteNamedRouteRule,
		// Extended: backend protocols
		features.SupportHTTPRouteBackendProtocolH2C,
		features.SupportHTTPRouteBackendProtocolWebSocket,
		// Extended: CORS
		features.SupportHTTPRouteCORS,
		// Extended: rule-level retry on upstream status codes (HTTPRouteRetry;
		// backoff and connection-error variants are not claimed).
		features.SupportHTTPRouteRetry,
		// Extended: port 8080 (non-standard listener port)
		features.SupportGatewayPort8080,
		// TLS
		features.SupportTLSRoute,
		features.SupportTLSRouteModeTerminate,
		features.SupportTLSRouteModeMixed,
		// gRPC
		features.SupportGRPCRoute,
		features.SupportGRPCRouteNamedRouteRule,
		// BackendTLSPolicy
		features.SupportBackendTLSPolicy,
		features.SupportBackendTLSPolicySANValidation,
		// mTLS: Gateway spec.tls.frontend (client certificate validation, strict and
		// AllowInsecureFallback) and spec.tls.backend.clientCertificateRef.
		features.SupportGatewayFrontendClientCertificateValidation,
		features.SupportGatewayFrontendClientCertificateValidationInsecureFallback,
		features.SupportGatewayBackendClientCertificate,
		// L4: TCPRoute and UDPRoute (GATEWAY-TCP / GATEWAY-UDP profiles).
		features.SupportTCPRoute,
		features.SupportUDPRoute,
	}

	// Allow skipping profiles via env var
	skip := map[suite.ConformanceProfileName]bool{
		suite.GatewayTLSConformanceProfileName:  os.Getenv("CONFORMANCE_SKIP_TLS") == "true",
		suite.GatewayGRPCConformanceProfileName: os.Getenv("CONFORMANCE_SKIP_GRPC") == "true",
	}
	opts.ConformanceProfiles = nil
	for _, p := range profiles {
		if !skip[p] {
			opts.ConformanceProfiles = append(opts.ConformanceProfiles, p)
		}
	}


	// Implementation metadata (required for report generation)
	opts.Implementation = confv1.Implementation{
		Organization: "Portus-Gateway",
		Project:      "portus-gateway",
		URL:          "https://github.com/Portus-Gateway/Portus",
		Version:      "0.2.0",
		Contact:      []string{"@Portus-Gateway"},
	}

	// Test isolation: give the controller time to process deletions between
	// tests. Without this, stale routes from the previous test can interfere
	// with the next test's routing expectations.
	opts.TimeoutConfig.TestIsolation = 2 * time.Second

	// Enable report generation for potential upstream submission
	opts.ReportOutputPath = "./conformance-report.yaml"

	conformance.RunConformanceWithOptions(t, opts)
}
