package grpc

import (
	"context"
	"io"
	"time"

	ext_proc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
)

type ExtProcServiceV3 struct {
	ext_proc.UnimplementedExternalProcessorServer
	authorizer auth.Authorizer
	logger     logger.Logger
}

func NewExtProcServiceV3(authorizer auth.Authorizer, log logger.Logger) *ExtProcServiceV3 {
	return &ExtProcServiceV3{
		authorizer: authorizer,
		logger:     log,
	}
}

func (s *ExtProcServiceV3) Process(stream ext_proc.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			s.logger.Error(ctx, "Error receiving from L3-L4 stream", map[string]interface{}{"error": err.Error()})
			return err
		}

		resp := s.processRequest(ctx, req)
		if err := stream.Send(resp); err != nil {
			s.logger.Error(ctx, "Error sending L3-L4 response", map[string]interface{}{"error": err.Error()})
			return err
		}
	}
}

func (s *ExtProcServiceV3) processRequest(ctx context.Context, req *ext_proc.ProcessingRequest) *ext_proc.ProcessingResponse {
	switch v := req.Request.(type) {
	case *ext_proc.ProcessingRequest_RequestHeaders:
		return s.processRequestHeaders(ctx, v.RequestHeaders)
	case *ext_proc.ProcessingRequest_RequestBody:
		return s.processRequestBody()
	case *ext_proc.ProcessingRequest_ResponseHeaders:
		return s.processResponseHeaders()
	case *ext_proc.ProcessingRequest_ResponseBody:
		return s.processResponseBody()
	default:
		return &ext_proc.ProcessingResponse{
			Response: &ext_proc.ProcessingResponse_ImmediateResponse{
				ImmediateResponse: &ext_proc.ImmediateResponse{
					Status: &envoy_type.HttpStatus{
						Code: envoy_type.StatusCode_Continue,
					},
				},
			},
		}
	}
}

func (s *ExtProcServiceV3) processRequestHeaders(ctx context.Context, headers *ext_proc.HttpHeaders) *ext_proc.ProcessingResponse {
	authReq := &auth.AuthRequest{
		RequestID: "ext-proc-request",
		Timestamp: time.Now(),
		Protocol:  "TCP",
	}

	authResp, err := s.authorizer.Authorize(ctx, authReq)
	if err != nil {
		s.logger.Error(ctx, "L3-L4 authorization failed", map[string]interface{}{"error": err.Error()})
	}

	if authResp != nil && authResp.Decision == auth.DecisionDeny {
		return &ext_proc.ProcessingResponse{
			Response: &ext_proc.ProcessingResponse_ImmediateResponse{
				ImmediateResponse: &ext_proc.ImmediateResponse{
					Status: &envoy_type.HttpStatus{
						Code: envoy_type.StatusCode_Forbidden,
					},
					Details: authResp.DeniedMessage,
				},
			},
		}
	}

	return &ext_proc.ProcessingResponse{
		Response: &ext_proc.ProcessingResponse_RequestHeaders{
			RequestHeaders: &ext_proc.HeadersResponse{},
		},
	}
}

func (s *ExtProcServiceV3) processRequestBody() *ext_proc.ProcessingResponse {
	return &ext_proc.ProcessingResponse{
		Response: &ext_proc.ProcessingResponse_RequestBody{
			RequestBody: &ext_proc.BodyResponse{},
		},
	}
}

func (s *ExtProcServiceV3) processResponseHeaders() *ext_proc.ProcessingResponse {
	return &ext_proc.ProcessingResponse{
		Response: &ext_proc.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &ext_proc.HeadersResponse{},
		},
	}
}

func (s *ExtProcServiceV3) processResponseBody() *ext_proc.ProcessingResponse {
	return &ext_proc.ProcessingResponse{
		Response: &ext_proc.ProcessingResponse_ResponseBody{
			ResponseBody: &ext_proc.BodyResponse{},
		},
	}
}
