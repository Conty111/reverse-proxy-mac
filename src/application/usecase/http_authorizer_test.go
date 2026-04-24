package usecase

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/ozontech/allure-go/pkg/allure"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/suite"

	"reverse-proxy-mac/src/domain/auth"
	infraldap "reverse-proxy-mac/src/infrastructure/ldap"
)

// HTTPAuthorizerSuite contains general HTTP authorization test cases
type HTTPAuthorizerSuite struct {
	suite.Suite
}

func TestHTTPAuthorizerSuiteRunner(t *testing.T) {
	suite.RunSuite(t, new(HTTPAuthorizerSuite))
}

func (s *HTTPAuthorizerSuite) BeforeAll(t provider.T) {
	t.Epic("HTTP Authorization")
	t.Feature("Kerberos Authentication & MAC Authorization")
}

// TestMissingAuthorizationHeader tests the case when Authorization header is missing
func (s *HTTPAuthorizerSuite) TestMissingAuthorizationHeader(t provider.T) {
	t.Title("Missing Authorization Header")
	t.Description("Should return 401 Unauthorized when Authorization header is missing")
	t.Tags("authentication", "negative")
	t.Severity(allure.CRITICAL)

	t.WithNewStep("Create authorizer", func(sCtx provider.StepCtx) {
		mockLog := &mockLogger{}
		mockLDAP := &infraldap.Client{Logger: mockLog}

		authorizer, err := NewHTTPAuthorizer(mockLog, mockLDAP, nil)
		sCtx.Require().NoError(err)
		sCtx.Require().NotNil(authorizer)

		t.WithNewStep("Prepare request without Authorization header", func(sCtx provider.StepCtx) {
			req := &auth.AuthRequest{
				RequestID:  "test-001",
				HTTPMethod: "GET",
				HTTPPath:   "/api/test",
				HTTPHeaders: map[string]string{
					"host": "example.com",
				},
			}

			t.WithNewStep("Execute authorization", func(sCtx provider.StepCtx) {
				ctx := context.Background()
				resp, err := authorizer.Authorize(ctx, req)

				sCtx.Require().NoError(err)
				sCtx.Require().NotNil(resp)

				t.WithNewStep("Verify response", func(sCtx provider.StepCtx) {
					sCtx.Assert().Equal(auth.DecisionDeny, resp.Decision)
					sCtx.Assert().Equal(int32(401), resp.DeniedStatus)
					sCtx.Assert().Equal("Kerberos authentication required", resp.DeniedMessage)
					sCtx.Assert().Equal("Kerberos authentication required", resp.Reason)
					sCtx.Assert().Equal(auth.DenyReasonAuthentication, resp.DenyReason)
					sCtx.Assert().NotEmpty(resp.DeniedBody)
					sCtx.Assert().Contains(resp.DeniedBody, `"reason":"AUTHENTICATION_REQUIRED"`)
					sCtx.Assert().Contains(resp.Headers, "WWW-Authenticate")
					sCtx.Assert().Equal("Negotiate", resp.Headers["WWW-Authenticate"])
				})
			})
		})
	})
}

// TestInvalidAuthorizationScheme tests the case when Authorization scheme is not Negotiate
func (s *HTTPAuthorizerSuite) TestInvalidAuthorizationScheme(t provider.T) {
	t.Title("Invalid Authorization Scheme")
	t.Description("Should return 401 when Authorization scheme is not 'Negotiate'")
	t.Tags("authentication", "negative")
	t.Severity(allure.CRITICAL)

	mockLog := &mockLogger{}
	mockLDAP := &infraldap.Client{Logger: mockLog}
	authorizer, _ := NewHTTPAuthorizer(mockLog, mockLDAP, nil)

	testCases := []struct {
		name   string
		header string
	}{
		{"Basic Auth", "Basic dXNlcjpwYXNz"},
		{"Bearer Token", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
		{"Digest Auth", "Digest username=\"user\""},
	}

	for _, tc := range testCases {
		t.WithNewStep("Test "+tc.name, func(sCtx provider.StepCtx) {
			req := &auth.AuthRequest{
				RequestID:  "test-002",
				HTTPMethod: "GET",
				HTTPHeaders: map[string]string{
					"authorization": tc.header,
					"host":          "example.com",
				},
			}

			ctx := context.Background()
			resp, err := authorizer.Authorize(ctx, req)

			sCtx.Require().NoError(err)
			sCtx.Assert().Equal(auth.DecisionDeny, resp.Decision)
			sCtx.Assert().Equal(int32(401), resp.DeniedStatus)
		})
	}
}

// TestInvalidBase64Token tests the case when Kerberos token is not valid base64
func (s *HTTPAuthorizerSuite) TestInvalidBase64Token(t provider.T) {
	t.Title("Invalid Base64 Kerberos Token")
	t.Description("Should return 401 when Kerberos token is not valid base64")
	t.Tags("authentication", "negative", "kerberos")
	t.Severity(allure.BLOCKER)

	mockLog := &mockLogger{}
	mockLDAP := &infraldap.Client{Logger: mockLog}
	authorizer, _ := NewHTTPAuthorizer(mockLog, mockLDAP, nil)

	req := &auth.AuthRequest{
		RequestID:  "test-003",
		HTTPMethod: "GET",
		HTTPHeaders: map[string]string{
			"authorization": "Negotiate !!!invalid-base64!!!",
			"host":          "example.com",
		},
	}

	ctx := context.Background()
	resp, err := authorizer.Authorize(ctx, req)

	t.Require().NoError(err)
	t.Assert().Equal(auth.DecisionDeny, resp.Decision)
	t.Assert().Equal(int32(401), resp.DeniedStatus)
}

// TestKerberosTicketVerificationFailed tests the case when Kerberos ticket verification fails
func (s *HTTPAuthorizerSuite) TestKerberosTicketVerificationFailed(t provider.T) {
	t.Title("Kerberos Ticket Verification Failed")
	t.Description("Should return 401 when Kerberos ticket verification fails")
	t.Tags("authentication", "negative", "kerberos")
	t.Severity(allure.BLOCKER)

	mockLog := &mockLogger{}
	mockLDAPBase := &infraldap.Client{Logger: mockLog}

	authorizer := &HTTPAuthorizer{
		logger:     mockLog,
		ldapClient: mockLDAPBase,
	}

	validToken := base64.StdEncoding.EncodeToString([]byte("fake-kerberos-token"))
	req := &auth.AuthRequest{
		RequestID:  "test-004",
		HTTPMethod: "GET",
		HTTPHeaders: map[string]string{
			"authorization": "Negotiate " + validToken,
			"host":          "example.com",
		},
	}

	ctx := context.Background()
	resp, err := authorizer.Authorize(ctx, req)

	// Should fail because VerifyKerberosTicket will fail with invalid token
	t.Require().NoError(err)
	t.Assert().Equal(auth.DecisionDeny, resp.Decision)
	t.Assert().Equal(int32(401), resp.DeniedStatus)
}

// TestExtractHostFromRequest tests host extraction from request
func (s *HTTPAuthorizerSuite) TestExtractHostFromRequest(t provider.T) {
	t.Title("Extract Host From Request")
	t.Description("Should correctly extract FQDN from various Host header formats")
	t.Tags("validation", "host")
	t.Severity(allure.NORMAL)

	testCases := []struct {
		name        string
		hostHeader  string
		expected    string
		shouldError bool
	}{
		{"Simple hostname", "example.com", "example.com", false},
		{"Hostname with port", "example.com:8080", "example.com", false},
		{"FQDN", "api.example.com", "api.example.com", false},
		{"FQDN with port", "api.example.com:443", "api.example.com", false},
		{"Empty header", "", "", true},
		{"Missing header", "", "", true},
	}

	for _, tc := range testCases {
		t.WithNewStep("Test: "+tc.name, func(sCtx provider.StepCtx) {
			req := &auth.AuthRequest{
				HTTPHeaders: map[string]string{},
			}

			if tc.hostHeader != "" {
				req.HTTPHeaders["host"] = tc.hostHeader
			}

			host, err := extractHostFromRequest(req)

			if tc.shouldError {
				sCtx.Assert().Error(err)
			} else {
				sCtx.Assert().NoError(err)
				sCtx.Assert().Equal(tc.expected, host)
			}
		})
	}
}

// TestValidateHTTPMethod tests HTTP method validation
func (s *HTTPAuthorizerSuite) TestValidateHTTPMethod(t provider.T) {
	t.Title("Validate HTTP Method")
	t.Description("Should validate standard HTTP methods")
	t.Tags("validation", "http-method")
	t.Severity(allure.NORMAL)

	validMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}

	t.WithNewStep("Test valid methods", func(sCtx provider.StepCtx) {
		for _, method := range validMethods {
			err := validateHTTPMethod(method)
			sCtx.Assert().NoError(err, "Method %s should be valid", method)
		}
	})

	t.WithNewStep("Test invalid methods", func(sCtx provider.StepCtx) {
		invalidMethods := []string{"", "INVALID"}
		for _, method := range invalidMethods {
			err := validateHTTPMethod(method)
			sCtx.Assert().Error(err, "Method %s should be invalid", method)
		}
	})

	t.WithNewStep("Test lowercase methods are accepted", func(sCtx provider.StepCtx) {
		// The validateHTTPMethod converts to uppercase, so lowercase is valid
		lowercaseMethods := []string{"get", "post", "put"}
		for _, method := range lowercaseMethods {
			err := validateHTTPMethod(method)
			sCtx.Assert().NoError(err, "Lowercase method %s should be accepted (converted to uppercase)", method)
		}
	})
}

// TestCreateUnauthorizedResponse tests the unauthorized response creation
func (s *HTTPAuthorizerSuite) TestCreateUnauthorizedResponse(t provider.T) {
	t.Title("Create Unauthorized Response")
	t.Description("Should create proper 401 Unauthorized response with Negotiate challenge")
	t.Tags("response", "authentication")
	t.Severity(allure.NORMAL)

	mockLog := &mockLogger{}
	mockLDAP := &infraldap.Client{Logger: mockLog}
	authorizer, _ := NewHTTPAuthorizer(mockLog, mockLDAP, nil)

	resp := authorizer.createUnauthorizedResponse()

	t.Assert().Equal(auth.DecisionDeny, resp.Decision)
	t.Assert().Equal(int32(401), resp.DeniedStatus)
	t.Assert().Equal("Kerberos authentication required", resp.DeniedMessage)
	t.Assert().Equal("Kerberos authentication required", resp.Reason)
	t.Assert().Equal(auth.DenyReasonAuthentication, resp.DenyReason)
	t.Assert().NotEmpty(resp.DeniedBody)
	t.Assert().Contains(resp.DeniedBody, `"reason":"AUTHENTICATION_REQUIRED"`)
	t.Assert().Contains(resp.DeniedBody, `"status":401`)
	t.Assert().Contains(resp.Headers, "WWW-Authenticate")
	t.Assert().Equal("Negotiate", resp.Headers["WWW-Authenticate"])
}
