package usecase

import (
	"testing"

	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/suite"

	"reverse-proxy-mac/src/domain/auth"
)

// MACAccessSuite contains MAC-specific test cases
type MACAccessSuite struct {
	suite.Suite
}

func (s *MACAccessSuite) BeforeAll(t provider.T) {
	t.Epic("HTTP Authorization")
	t.Feature("MAC Access Control")
	t.Story("MAC Authorization")
}

// TestMACAuthorizationDeniedReadOperation tests MAC denial for read operations
func (s *MACAccessSuite) TestMACAuthorizationDeniedReadOperation(t provider.T) {
	t.Title("MAC Denied - Read Operation (User Level < Host Level)")
	t.Description("Should deny access when user confidentiality level is lower than host level for read operations")
	t.Tags("authorization", "mac", "negative")
	t.Severity(allure.BLOCKER)

	// Test the checkAccessHTTP function directly
	userCtx := &auth.UserHTTPSecurityContext{
		RequestMethod:   "GET",
		Confidentiality: 1, // User level 1
		Categories:      0xFF,
		Capabilities:    0xFF,
		Integrity:       0xFF,
	}

	hostCtx := &auth.HostSecurityContext{
		Confidentiality: 2, // Host level 2 (higher than user)
		Categories:      0,
		Capabilities:    0,
		Integrity:       0,
	}

	allowed, reason := checkAccessHTTP(userCtx, hostCtx)

	t.Assert().False(allowed)
	t.Assert().Contains(reason, "user level")
	t.Assert().Contains(reason, "host level")
}

// TestMACAuthorizationDeniedWriteOperation tests MAC denial for write operations
func (s *MACAccessSuite) TestMACAuthorizationDeniedWriteOperation(t provider.T) {
	t.Title("MAC Denied - Write Operation (User Level != Host Level)")
	t.Description("Should deny access when user level doesn't equal host level for write operations")
	t.Tags("authorization", "mac", "negative", "write")
	t.Severity(allure.BLOCKER)

	userCtx := &auth.UserHTTPSecurityContext{
		RequestMethod:   "POST",
		Confidentiality: 3, // User level 3
		Categories:      0xFF,
		Capabilities:    0xFF,
		Integrity:       0xFF,
	}

	hostCtx := &auth.HostSecurityContext{
		Confidentiality: 2, // Host level 2 (different from user)
		Categories:      0,
		Capabilities:    0,
		Integrity:       0,
	}

	allowed, reason := checkAccessHTTP(userCtx, hostCtx)

	t.Assert().False(allowed)
	t.Assert().Contains(reason, "write operation denied")
}

// TestMACAuthorizationDeniedCategories tests MAC denial due to missing categories
func (s *MACAccessSuite) TestMACAuthorizationDeniedCategories(t provider.T) {
	t.Title("MAC Denied - Missing Required Categories")
	t.Description("Should deny access when user doesn't have all required categories")
	t.Tags("authorization", "mac", "negative", "categories")
	t.Severity(allure.BLOCKER)

	userCtx := &auth.UserHTTPSecurityContext{
		RequestMethod:   "GET",
		Confidentiality: 2,
		Categories:      0x0F, // User has only lower bits
		Capabilities:    0xFF,
		Integrity:       0xFF,
	}

	hostCtx := &auth.HostSecurityContext{
		Confidentiality: 2,
		Categories:      0xFF, // Host requires more bits
		Capabilities:    0,
		Integrity:       0,
	}

	allowed, reason := checkAccessHTTP(userCtx, hostCtx)

	t.Assert().False(allowed)
	t.Assert().Contains(reason, "categories")
}

// TestMACAuthorizationDeniedIntegrity tests MAC denial due to insufficient integrity level
func (s *MACAccessSuite) TestMACAuthorizationDeniedIntegrity(t provider.T) {
	t.Title("MAC Denied - Insufficient Integrity Level")
	t.Description("Should deny access when user integrity level is lower than host integrity level")
	t.Tags("authorization", "mac", "negative", "integrity")
	t.Severity(allure.BLOCKER)

	userCtx := &auth.UserHTTPSecurityContext{
		RequestMethod:   "GET",
		Confidentiality: 2,
		Categories:      0xFF,
		Capabilities:    0xFF,
		Integrity:       0x10, // Low integrity
	}

	hostCtx := &auth.HostSecurityContext{
		Confidentiality: 2,
		Categories:      0,
		Capabilities:    0,
		Integrity:       0xFF, // High integrity required
	}

	allowed, reason := checkAccessHTTP(userCtx, hostCtx)

	t.Assert().False(allowed)
	t.Assert().Contains(reason, "integrity")
}

// TestMACAuthorizationDeniedCapabilities tests MAC denial due to missing capabilities
func (s *MACAccessSuite) TestMACAuthorizationDeniedCapabilities(t provider.T) {
	t.Title("MAC Denied - Missing Required Capabilities")
	t.Description("Should deny access when user doesn't have all required capabilities")
	t.Tags("authorization", "mac", "negative", "capabilities")
	t.Severity(allure.BLOCKER)

	userCtx := &auth.UserHTTPSecurityContext{
		RequestMethod:   "GET",
		Confidentiality: 2,
		Categories:      0xFF,
		Capabilities:    0x0F, // Limited capabilities
		Integrity:       0xFF,
	}

	hostCtx := &auth.HostSecurityContext{
		Confidentiality: 2,
		Categories:      0,
		Capabilities:    0xFF, // More capabilities required
		Integrity:       0,
	}

	allowed, reason := checkAccessHTTP(userCtx, hostCtx)

	t.Assert().False(allowed)
	t.Assert().Contains(reason, "capabilities")
}

// TestSuccessfulMACAuthorizationReadOperation tests successful MAC authorization for read operations
func (s *MACAccessSuite) TestSuccessfulMACAuthorizationReadOperation(t provider.T) {
	t.Title("MAC Allow - Read Operation")
	t.Description("Should allow access when all MAC checks pass for read operation")
	t.Tags("authorization", "mac", "positive", "read")
	t.Severity(allure.BLOCKER)

	userCtx := &auth.UserHTTPSecurityContext{
		RequestMethod:   "GET",
		Confidentiality: 3, // User level >= host level
		Categories:      0xFF,
		Capabilities:    0xFF,
		Integrity:       0xFF,
	}

	hostCtx := &auth.HostSecurityContext{
		Confidentiality: 2,
		Categories:      0x0F,
		Capabilities:    0x0F,
		Integrity:       0x0F,
	}

	allowed, reason := checkAccessHTTP(userCtx, hostCtx)

	t.Assert().True(allowed)
	t.Assert().Contains(reason, "access granted")
}

// TestSuccessfulMACAuthorizationWriteOperation tests successful MAC authorization for write operations
func (s *MACAccessSuite) TestSuccessfulMACAuthorizationWriteOperation(t provider.T) {
	t.Title("MAC Allow - Write Operation")
	t.Description("Should allow access when user level equals host level for write operation")
	t.Tags("authorization", "mac", "positive", "write")
	t.Severity(allure.BLOCKER)

	writeMethods := []string{"POST", "PUT", "DELETE", "PATCH"}

	for _, method := range writeMethods {
		t.WithNewStep("Test "+method+" method", func(sCtx provider.StepCtx) {
			userCtx := &auth.UserHTTPSecurityContext{
				RequestMethod:   method,
				Confidentiality: 2, // User level == host level
				Categories:      0xFF,
				Capabilities:    0xFF,
				Integrity:       0xFF,
			}

			hostCtx := &auth.HostSecurityContext{
				Confidentiality: 2,
				Categories:      0x0F,
				Capabilities:    0x0F,
				Integrity:       0x0F,
			}

			allowed, reason := checkAccessHTTP(userCtx, hostCtx)

			sCtx.Assert().True(allowed)
			sCtx.Assert().Contains(reason, "access granted")
		})
	}
}

// TestCheckMACAccessEdgeCases tests edge cases in MAC access control
func (s *MACAccessSuite) TestCheckMACAccessEdgeCases(t provider.T) {
	t.Title("MAC Access Control - Edge Cases")
	t.Description("Should handle edge cases like zero values and maximum values correctly")
	t.Tags("authorization", "mac", "edge-cases")
	t.Severity(allure.NORMAL)

	t.WithNewStep("Test zero values - should allow", func(sCtx provider.StepCtx) {
		userCtx := &auth.UserHTTPSecurityContext{
			RequestMethod:   "GET",
			Confidentiality: 0,
			Categories:      0,
			Capabilities:    0,
			Integrity:       0,
		}

		hostCtx := &auth.HostSecurityContext{
			Confidentiality: 0,
			Categories:      0,
			Capabilities:    0,
			Integrity:       0,
		}

		allowed, _ := checkMACAccess(userCtx, hostCtx, false)
		sCtx.Assert().True(allowed)
	})

	t.WithNewStep("Test max values - should allow", func(sCtx provider.StepCtx) {
		userCtx := &auth.UserHTTPSecurityContext{
			RequestMethod:   "GET",
			Confidentiality: 255,
			Categories:      0xFFFFFFFFFFFFFFFF,
			Capabilities:    0xFFFFFFFFFFFFFFFF,
			Integrity:       0xFFFFFFFF,
		}

		hostCtx := &auth.HostSecurityContext{
			Confidentiality: 255,
			Categories:      0xFFFFFFFFFFFFFFFF,
			Capabilities:    0xFFFFFFFFFFFFFFFF,
			Integrity:       0xFFFFFFFF,
		}

		allowed, _ := checkMACAccess(userCtx, hostCtx, false)
		sCtx.Assert().True(allowed)
	})
}

func TestMACAccessSuiteRunner(t *testing.T) {
	suite.RunSuite(t, new(MACAccessSuite))
}
