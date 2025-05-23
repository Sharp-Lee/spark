// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: frost.proto

package frost

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	FrostService_Echo_FullMethodName                   = "/frost.FrostService/echo"
	FrostService_DkgRound1_FullMethodName              = "/frost.FrostService/dkg_round1"
	FrostService_DkgRound2_FullMethodName              = "/frost.FrostService/dkg_round2"
	FrostService_DkgRound3_FullMethodName              = "/frost.FrostService/dkg_round3"
	FrostService_FrostNonce_FullMethodName             = "/frost.FrostService/frost_nonce"
	FrostService_SignFrost_FullMethodName              = "/frost.FrostService/sign_frost"
	FrostService_AggregateFrost_FullMethodName         = "/frost.FrostService/aggregate_frost"
	FrostService_ValidateSignatureShare_FullMethodName = "/frost.FrostService/validate_signature_share"
)

// FrostServiceClient is the client API for FrostService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type FrostServiceClient interface {
	Echo(ctx context.Context, in *EchoRequest, opts ...grpc.CallOption) (*EchoResponse, error)
	DkgRound1(ctx context.Context, in *DkgRound1Request, opts ...grpc.CallOption) (*DkgRound1Response, error)
	DkgRound2(ctx context.Context, in *DkgRound2Request, opts ...grpc.CallOption) (*DkgRound2Response, error)
	DkgRound3(ctx context.Context, in *DkgRound3Request, opts ...grpc.CallOption) (*DkgRound3Response, error)
	FrostNonce(ctx context.Context, in *FrostNonceRequest, opts ...grpc.CallOption) (*FrostNonceResponse, error)
	SignFrost(ctx context.Context, in *SignFrostRequest, opts ...grpc.CallOption) (*SignFrostResponse, error)
	AggregateFrost(ctx context.Context, in *AggregateFrostRequest, opts ...grpc.CallOption) (*AggregateFrostResponse, error)
	ValidateSignatureShare(ctx context.Context, in *ValidateSignatureShareRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type frostServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewFrostServiceClient(cc grpc.ClientConnInterface) FrostServiceClient {
	return &frostServiceClient{cc}
}

func (c *frostServiceClient) Echo(ctx context.Context, in *EchoRequest, opts ...grpc.CallOption) (*EchoResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(EchoResponse)
	err := c.cc.Invoke(ctx, FrostService_Echo_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *frostServiceClient) DkgRound1(ctx context.Context, in *DkgRound1Request, opts ...grpc.CallOption) (*DkgRound1Response, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DkgRound1Response)
	err := c.cc.Invoke(ctx, FrostService_DkgRound1_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *frostServiceClient) DkgRound2(ctx context.Context, in *DkgRound2Request, opts ...grpc.CallOption) (*DkgRound2Response, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DkgRound2Response)
	err := c.cc.Invoke(ctx, FrostService_DkgRound2_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *frostServiceClient) DkgRound3(ctx context.Context, in *DkgRound3Request, opts ...grpc.CallOption) (*DkgRound3Response, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DkgRound3Response)
	err := c.cc.Invoke(ctx, FrostService_DkgRound3_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *frostServiceClient) FrostNonce(ctx context.Context, in *FrostNonceRequest, opts ...grpc.CallOption) (*FrostNonceResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(FrostNonceResponse)
	err := c.cc.Invoke(ctx, FrostService_FrostNonce_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *frostServiceClient) SignFrost(ctx context.Context, in *SignFrostRequest, opts ...grpc.CallOption) (*SignFrostResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SignFrostResponse)
	err := c.cc.Invoke(ctx, FrostService_SignFrost_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *frostServiceClient) AggregateFrost(ctx context.Context, in *AggregateFrostRequest, opts ...grpc.CallOption) (*AggregateFrostResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AggregateFrostResponse)
	err := c.cc.Invoke(ctx, FrostService_AggregateFrost_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *frostServiceClient) ValidateSignatureShare(ctx context.Context, in *ValidateSignatureShareRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, FrostService_ValidateSignatureShare_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FrostServiceServer is the server API for FrostService service.
// All implementations must embed UnimplementedFrostServiceServer
// for forward compatibility.
type FrostServiceServer interface {
	Echo(context.Context, *EchoRequest) (*EchoResponse, error)
	DkgRound1(context.Context, *DkgRound1Request) (*DkgRound1Response, error)
	DkgRound2(context.Context, *DkgRound2Request) (*DkgRound2Response, error)
	DkgRound3(context.Context, *DkgRound3Request) (*DkgRound3Response, error)
	FrostNonce(context.Context, *FrostNonceRequest) (*FrostNonceResponse, error)
	SignFrost(context.Context, *SignFrostRequest) (*SignFrostResponse, error)
	AggregateFrost(context.Context, *AggregateFrostRequest) (*AggregateFrostResponse, error)
	ValidateSignatureShare(context.Context, *ValidateSignatureShareRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedFrostServiceServer()
}

// UnimplementedFrostServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedFrostServiceServer struct{}

func (UnimplementedFrostServiceServer) Echo(context.Context, *EchoRequest) (*EchoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Echo not implemented")
}
func (UnimplementedFrostServiceServer) DkgRound1(context.Context, *DkgRound1Request) (*DkgRound1Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DkgRound1 not implemented")
}
func (UnimplementedFrostServiceServer) DkgRound2(context.Context, *DkgRound2Request) (*DkgRound2Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DkgRound2 not implemented")
}
func (UnimplementedFrostServiceServer) DkgRound3(context.Context, *DkgRound3Request) (*DkgRound3Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DkgRound3 not implemented")
}
func (UnimplementedFrostServiceServer) FrostNonce(context.Context, *FrostNonceRequest) (*FrostNonceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FrostNonce not implemented")
}
func (UnimplementedFrostServiceServer) SignFrost(context.Context, *SignFrostRequest) (*SignFrostResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignFrost not implemented")
}
func (UnimplementedFrostServiceServer) AggregateFrost(context.Context, *AggregateFrostRequest) (*AggregateFrostResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AggregateFrost not implemented")
}
func (UnimplementedFrostServiceServer) ValidateSignatureShare(context.Context, *ValidateSignatureShareRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateSignatureShare not implemented")
}
func (UnimplementedFrostServiceServer) mustEmbedUnimplementedFrostServiceServer() {}
func (UnimplementedFrostServiceServer) testEmbeddedByValue()                      {}

// UnsafeFrostServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to FrostServiceServer will
// result in compilation errors.
type UnsafeFrostServiceServer interface {
	mustEmbedUnimplementedFrostServiceServer()
}

func RegisterFrostServiceServer(s grpc.ServiceRegistrar, srv FrostServiceServer) {
	// If the following call pancis, it indicates UnimplementedFrostServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&FrostService_ServiceDesc, srv)
}

func _FrostService_Echo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EchoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FrostServiceServer).Echo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FrostService_Echo_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FrostServiceServer).Echo(ctx, req.(*EchoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FrostService_DkgRound1_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DkgRound1Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FrostServiceServer).DkgRound1(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FrostService_DkgRound1_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FrostServiceServer).DkgRound1(ctx, req.(*DkgRound1Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _FrostService_DkgRound2_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DkgRound2Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FrostServiceServer).DkgRound2(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FrostService_DkgRound2_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FrostServiceServer).DkgRound2(ctx, req.(*DkgRound2Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _FrostService_DkgRound3_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DkgRound3Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FrostServiceServer).DkgRound3(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FrostService_DkgRound3_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FrostServiceServer).DkgRound3(ctx, req.(*DkgRound3Request))
	}
	return interceptor(ctx, in, info, handler)
}

func _FrostService_FrostNonce_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FrostNonceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FrostServiceServer).FrostNonce(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FrostService_FrostNonce_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FrostServiceServer).FrostNonce(ctx, req.(*FrostNonceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FrostService_SignFrost_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignFrostRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FrostServiceServer).SignFrost(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FrostService_SignFrost_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FrostServiceServer).SignFrost(ctx, req.(*SignFrostRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FrostService_AggregateFrost_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AggregateFrostRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FrostServiceServer).AggregateFrost(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FrostService_AggregateFrost_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FrostServiceServer).AggregateFrost(ctx, req.(*AggregateFrostRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FrostService_ValidateSignatureShare_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidateSignatureShareRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FrostServiceServer).ValidateSignatureShare(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: FrostService_ValidateSignatureShare_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FrostServiceServer).ValidateSignatureShare(ctx, req.(*ValidateSignatureShareRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// FrostService_ServiceDesc is the grpc.ServiceDesc for FrostService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var FrostService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "frost.FrostService",
	HandlerType: (*FrostServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "echo",
			Handler:    _FrostService_Echo_Handler,
		},
		{
			MethodName: "dkg_round1",
			Handler:    _FrostService_DkgRound1_Handler,
		},
		{
			MethodName: "dkg_round2",
			Handler:    _FrostService_DkgRound2_Handler,
		},
		{
			MethodName: "dkg_round3",
			Handler:    _FrostService_DkgRound3_Handler,
		},
		{
			MethodName: "frost_nonce",
			Handler:    _FrostService_FrostNonce_Handler,
		},
		{
			MethodName: "sign_frost",
			Handler:    _FrostService_SignFrost_Handler,
		},
		{
			MethodName: "aggregate_frost",
			Handler:    _FrostService_AggregateFrost_Handler,
		},
		{
			MethodName: "validate_signature_share",
			Handler:    _FrostService_ValidateSignatureShare_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "frost.proto",
}
