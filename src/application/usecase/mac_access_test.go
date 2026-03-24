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
	t.Title("MAC Denied - Read Operation (Ranges do not overlap)")
	t.Description("Should deny access when user confidentiality range does not overlap with host range for read operations")
	t.Tags("authorization", "mac", "negative")
	t.Severity(allure.BLOCKER)

	// Test the checkAccessHTTP function directly
	userCtx := &auth.UserHTTPSecurityContext{
		RequestMethod:       "GET",
		ConfidentialityMin:  1,
		ConfidentialityMax:  1, // User range [1, 1]
		CategoriesMin:       0xFF,
		CategoriesMax:       0xFF,
		IntegrityCategories: 0xFF,
	}

	hostCtx := &auth.HostSecurityContext{
		ConfidentialityMin:  2,
		ConfidentialityMax:  3, // Host range [2, 3] (no overlap)
		CategoriesMin:       0,
		CategoriesMax:       0,
		IntegrityCategories: 0,
	}

	allowed, reason := checkAccessHTTP(userCtx, hostCtx)

	t.Assert().False(allowed)
	t.Assert().Contains(reason, "does not overlap")
}

// TestMACAuthorizationDeniedWriteOperation tests MAC denial for write operations
func (s *MACAccessSuite) TestMACAuthorizationDeniedWriteOperation(t provider.T) {
	t.Title("MAC Denied - Write Operation (Ranges do not match exactly)")
	t.Description("Should deny access when user range doesn't exactly match host range for write operations")
	t.Tags("authorization", "mac", "negative", "write")
	t.Severity(allure.BLOCKER)

	userCtx := &auth.UserHTTPSecurityContext{
		RequestMethod:       "POST",
		ConfidentialityMin:  2,
		ConfidentialityMax:  3, // User range [2, 3]
		CategoriesMin:       0xFF,
		CategoriesMax:       0xFF,
		IntegrityCategories: 0xFF,
	}

	hostCtx := &auth.HostSecurityContext{
		ConfidentialityMin:  2,
		ConfidentialityMax:  2, // Host range [2, 2] (different)
		CategoriesMin:       0,
		CategoriesMax:       0,
		IntegrityCategories: 0,
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
		RequestMethod:       "GET",
		ConfidentialityMin:  2,
		ConfidentialityMax:  2,
		CategoriesMin:       0x0F,
		CategoriesMax:       0x0F, // User has only lower bits
		IntegrityCategories: 0xFF,
	}

	hostCtx := &auth.HostSecurityContext{
		ConfidentialityMin:  2,
		ConfidentialityMax:  2,
		CategoriesMin:       0xFF, // Host requires more bits
		CategoriesMax:       0xFF,
		IntegrityCategories: 0,
	}

	allowed, reason := checkAccessHTTP(userCtx, hostCtx)

	t.Assert().False(allowed)
	t.Assert().Contains(reason, "categories")
}

// TestMACAuthorizationDeniedIntegrity tests MAC denial due to insufficient integrity level
func (s *MACAccessSuite) TestMACAuthorizationDeniedIntegrity(t provider.T) {
	t.Title("MAC Denied - Insufficient Integrity Categories")
	t.Description("Should deny access when user integrity categories do not include all host integrity categories")
	t.Tags("authorization", "mac", "negative", "integrity")
	t.Severity(allure.BLOCKER)

	userCtx := &auth.UserHTTPSecurityContext{
		RequestMethod:       "GET",
		ConfidentialityMin:  2,
		ConfidentialityMax:  2,
		CategoriesMin:       0xFF,
		CategoriesMax:       0xFF,
		IntegrityCategories: 0x10, // Low integrity
	}

	hostCtx := &auth.HostSecurityContext{
		ConfidentialityMin:  2,
		ConfidentialityMax:  2,
		CategoriesMin:       0,
		CategoriesMax:       0,
		IntegrityCategories: 0xFF, // High integrity required
	}

	allowed, reason := checkAccessHTTP(userCtx, hostCtx)

	t.Assert().False(allowed)
	t.Assert().Contains(reason, "integrity")
}

// TestSuccessfulMACAuthorizationReadOperation tests successful MAC authorization for read operations
func (s *MACAccessSuite) TestSuccessfulMACAuthorizationReadOperation(t provider.T) {
	t.Title("MAC Allow - Read Operation")
	t.Description("Should allow access when all MAC checks pass for read operation")
	t.Tags("authorization", "mac", "positive", "read")
	t.Severity(allure.BLOCKER)

	userCtx := &auth.UserHTTPSecurityContext{
		RequestMethod:       "GET",
		ConfidentialityMin:  1,
		ConfidentialityMax:  3, // User range [1, 3] overlaps with [2, 2]
		CategoriesMin:       0xFF,
		CategoriesMax:       0xFF,
		IntegrityCategories: 0xFF,
	}

	hostCtx := &auth.HostSecurityContext{
		ConfidentialityMin:  2,
		ConfidentialityMax:  2,
		CategoriesMin:       0x0F,
		CategoriesMax:       0x0F,
		IntegrityCategories: 0x0F,
	}

	allowed, reason := checkAccessHTTP(userCtx, hostCtx)

	t.Assert().True(allowed)
	t.Assert().Contains(reason, "access granted")
}

// TestSuccessfulMACAuthorizationWriteOperation tests successful MAC authorization for write operations
func (s *MACAccessSuite) TestSuccessfulMACAuthorizationWriteOperation(t provider.T) {
	t.Title("MAC Allow - Write Operation")
	t.Description("Should allow access when user range equals host range for write operation")
	t.Tags("authorization", "mac", "positive", "write")
	t.Severity(allure.BLOCKER)

	writeMethods := []string{"POST", "PUT", "DELETE", "PATCH"}

	for _, method := range writeMethods {
		t.WithNewStep("Test "+method+" method", func(sCtx provider.StepCtx) {
			userCtx := &auth.UserHTTPSecurityContext{
				RequestMethod:       method,
				ConfidentialityMin:  2,
				ConfidentialityMax:  3, // User range == host range
				CategoriesMin:       0xFF,
				CategoriesMax:       0xFF,
				IntegrityCategories: 0xFF,
			}

			hostCtx := &auth.HostSecurityContext{
				ConfidentialityMin:  2,
				ConfidentialityMax:  3,
				CategoriesMin:       0xFF,
				CategoriesMax:       0xFF,
				IntegrityCategories: 0x0F,
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
			RequestMethod:       "GET",
			ConfidentialityMin:  0,
			ConfidentialityMax:  0,
			CategoriesMin:       0,
			CategoriesMax:       0,
			IntegrityCategories: 0,
		}

		hostCtx := &auth.HostSecurityContext{
			ConfidentialityMin:  0,
			ConfidentialityMax:  0,
			CategoriesMin:       0,
			CategoriesMax:       0,
			IntegrityCategories: 0,
		}

		allowed, _ := checkMACAccess(userCtx, hostCtx, false)
		sCtx.Assert().True(allowed)
	})

	t.WithNewStep("Test max values - should allow", func(sCtx provider.StepCtx) {
		userCtx := &auth.UserHTTPSecurityContext{
			RequestMethod:       "GET",
			ConfidentialityMin:  255,
			ConfidentialityMax:  255,
			CategoriesMin:       0xFFFFFFFFFFFFFFFF,
			CategoriesMax:       0xFFFFFFFFFFFFFFFF,
			IntegrityCategories: 0xFFFFFFFF,
		}

		hostCtx := &auth.HostSecurityContext{
			ConfidentialityMin:  255,
			ConfidentialityMax:  255,
			CategoriesMin:       0xFFFFFFFFFFFFFFFF,
			CategoriesMax:       0xFFFFFFFFFFFFFFFF,
			IntegrityCategories: 0xFFFFFFFF,
		}

		allowed, _ := checkMACAccess(userCtx, hostCtx, false)
		sCtx.Assert().True(allowed)
	})
}

func TestMACAccessSuiteRunner(t *testing.T) {
	suite.RunSuite(t, new(MACAccessSuite))
}
