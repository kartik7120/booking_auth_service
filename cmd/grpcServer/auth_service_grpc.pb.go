// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.2
// source: auth_service.proto

package auth

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	AuthService_Resigter_FullMethodName              = "/auth.AuthService/Resigter"
	AuthService_Login_FullMethodName                 = "/auth.AuthService/Login"
	AuthService_ValidateToken_FullMethodName         = "/auth.AuthService/ValidateToken"
	AuthService_SendResetPasswordMail_FullMethodName = "/auth.AuthService/SendResetPasswordMail"
	AuthService_ResetPassword_FullMethodName         = "/auth.AuthService/ResetPassword"
)

// AuthServiceClient is the client API for AuthService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AuthServiceClient interface {
	Resigter(ctx context.Context, in *User, opts ...grpc.CallOption) (*Response, error)
	Login(ctx context.Context, in *LoginUser, opts ...grpc.CallOption) (*Response, error)
	ValidateToken(ctx context.Context, in *ValdateTokenRequest, opts ...grpc.CallOption) (*ValidateTokenResponse, error)
	SendResetPasswordMail(ctx context.Context, in *SendResetPasswordMailRequest, opts ...grpc.CallOption) (*Response, error)
	ResetPassword(ctx context.Context, in *ResetPasswordRequest, opts ...grpc.CallOption) (*Response, error)
}

type authServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAuthServiceClient(cc grpc.ClientConnInterface) AuthServiceClient {
	return &authServiceClient{cc}
}

func (c *authServiceClient) Resigter(ctx context.Context, in *User, opts ...grpc.CallOption) (*Response, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Response)
	err := c.cc.Invoke(ctx, AuthService_Resigter_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) Login(ctx context.Context, in *LoginUser, opts ...grpc.CallOption) (*Response, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Response)
	err := c.cc.Invoke(ctx, AuthService_Login_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) ValidateToken(ctx context.Context, in *ValdateTokenRequest, opts ...grpc.CallOption) (*ValidateTokenResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ValidateTokenResponse)
	err := c.cc.Invoke(ctx, AuthService_ValidateToken_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) SendResetPasswordMail(ctx context.Context, in *SendResetPasswordMailRequest, opts ...grpc.CallOption) (*Response, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Response)
	err := c.cc.Invoke(ctx, AuthService_SendResetPasswordMail_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) ResetPassword(ctx context.Context, in *ResetPasswordRequest, opts ...grpc.CallOption) (*Response, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Response)
	err := c.cc.Invoke(ctx, AuthService_ResetPassword_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthServiceServer is the server API for AuthService service.
// All implementations must embed UnimplementedAuthServiceServer
// for forward compatibility.
type AuthServiceServer interface {
	Resigter(context.Context, *User) (*Response, error)
	Login(context.Context, *LoginUser) (*Response, error)
	ValidateToken(context.Context, *ValdateTokenRequest) (*ValidateTokenResponse, error)
	SendResetPasswordMail(context.Context, *SendResetPasswordMailRequest) (*Response, error)
	ResetPassword(context.Context, *ResetPasswordRequest) (*Response, error)
	mustEmbedUnimplementedAuthServiceServer()
}

// UnimplementedAuthServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedAuthServiceServer struct{}

func (UnimplementedAuthServiceServer) Resigter(context.Context, *User) (*Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Resigter not implemented")
}
func (UnimplementedAuthServiceServer) Login(context.Context, *LoginUser) (*Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedAuthServiceServer) ValidateToken(context.Context, *ValdateTokenRequest) (*ValidateTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateToken not implemented")
}
func (UnimplementedAuthServiceServer) SendResetPasswordMail(context.Context, *SendResetPasswordMailRequest) (*Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendResetPasswordMail not implemented")
}
func (UnimplementedAuthServiceServer) ResetPassword(context.Context, *ResetPasswordRequest) (*Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ResetPassword not implemented")
}
func (UnimplementedAuthServiceServer) mustEmbedUnimplementedAuthServiceServer() {}
func (UnimplementedAuthServiceServer) testEmbeddedByValue()                     {}

// UnsafeAuthServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AuthServiceServer will
// result in compilation errors.
type UnsafeAuthServiceServer interface {
	mustEmbedUnimplementedAuthServiceServer()
}

func RegisterAuthServiceServer(s grpc.ServiceRegistrar, srv AuthServiceServer) {
	// If the following call pancis, it indicates UnimplementedAuthServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&AuthService_ServiceDesc, srv)
}

func _AuthService_Resigter_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(User)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).Resigter(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_Resigter_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).Resigter(ctx, req.(*User))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginUser)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_Login_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).Login(ctx, req.(*LoginUser))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_ValidateToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValdateTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).ValidateToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_ValidateToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).ValidateToken(ctx, req.(*ValdateTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_SendResetPasswordMail_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendResetPasswordMailRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).SendResetPasswordMail(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_SendResetPasswordMail_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).SendResetPasswordMail(ctx, req.(*SendResetPasswordMailRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_ResetPassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResetPasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).ResetPassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_ResetPassword_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).ResetPassword(ctx, req.(*ResetPasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AuthService_ServiceDesc is the grpc.ServiceDesc for AuthService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AuthService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "auth.AuthService",
	HandlerType: (*AuthServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Resigter",
			Handler:    _AuthService_Resigter_Handler,
		},
		{
			MethodName: "Login",
			Handler:    _AuthService_Login_Handler,
		},
		{
			MethodName: "ValidateToken",
			Handler:    _AuthService_ValidateToken_Handler,
		},
		{
			MethodName: "SendResetPasswordMail",
			Handler:    _AuthService_SendResetPasswordMail_Handler,
		},
		{
			MethodName: "ResetPassword",
			Handler:    _AuthService_ResetPassword_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "auth_service.proto",
}
