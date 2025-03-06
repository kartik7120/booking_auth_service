package server

import (
	"context"
	"time"

	"github.com/kartik7120/booking_auth_service/cmd/auth"
	au "github.com/kartik7120/booking_auth_service/cmd/grpcServer"
	"github.com/kartik7120/booking_auth_service/cmd/models"
)

type AuthService struct {
	au.UnimplementedAuthServiceServer
	Authentication *auth.Authentication
}

func (a *AuthService) Resigter(ctx context.Context, in *au.User) (*au.Response, error) {

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if ctx.Err() != nil {
		return &au.Response{
			Status:  408,
			Message: "Context was cancelled",
			Error:   "",
		}, ctx.Err()
	}

	user := models.User{
		Username: in.Username,
		Email:    in.Email,
		Password: in.Password,
	}

	token, status, err := a.Authentication.Register(user)

	if ctx.Err() == context.Canceled {
		cancel()
		return &au.Response{
			Status:  408,
			Message: "Context was cancelled",
			Error:   "",
		}, ctx.Err()
	}

	if err != nil {
		return &au.Response{
			Status:  int32(status),
			Message: "Failed to register user",
			Error:   err.Error(),
		}, err
	}

	return &au.Response{
		Status:  int32(status),
		Message: "User registered successfully",
		Token:   token,
	}, nil
}

func (a *AuthService) Login(ctx context.Context, in *au.LoginUser) (*au.Response, error) {

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if ctx.Err() != nil {
		return &au.Response{
			Status:  408,
			Message: "Context was cancelled",
			Error:   ctx.Err().Error(),
		}, ctx.Err()
	}

	user := models.LoginUser{
		Username: in.Username,
		Password: in.Password,
	}

	token, status, err := a.Authentication.Login(user)

	if ctx.Err() == context.Canceled {
		cancel()
		return &au.Response{
			Status:  408,
			Message: "Context was cancelled",
			Error:   ctx.Err().Error(),
		}, ctx.Err()
	}

	if err != nil {
		return &au.Response{
			Status:  int32(status),
			Message: "Failed to login user",
			Error:   err.Error(),
		}, err
	}

	return &au.Response{
		Status:  int32(status),
		Message: "User logged in successfully",
		Token:   token,
	}, nil
}

func (a *AuthService) ValidateToken(ctx context.Context, in *au.ValdateTokenRequest) (*au.ValidateTokenResponse, error) {

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if ctx.Err() != nil {
		cancel()
		return &au.ValidateTokenResponse{
			Valid:  false,
			Error:  ctx.Err().Error(),
			Status: 408,
		}, ctx.Err()
	}

	isValid, status, err := a.Authentication.ValidateToken(in.Token)

	if ctx.Err() == context.Canceled {
		cancel()
		return &au.ValidateTokenResponse{
			Valid:  false,
			Error:  "Context was cancelled",
			Status: 408,
		}, ctx.Err()
	}

	if err != nil {
		return &au.ValidateTokenResponse{
			Valid:  false,
			Error:  err.Error(),
			Status: int32(status),
		}, err
	}

	if isValid {
		return &au.ValidateTokenResponse{
			Valid:  true,
			Error:  "",
			Status: 200,
		}, nil
	}

	return &au.ValidateTokenResponse{
		Valid:  false,
		Error:  "",
		Status: 403,
	}, nil
}

func (a *AuthService) SendResetPasswordMail(ctx context.Context, in *au.SendResetPasswordMailRequest) (*au.Response, error) {

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if ctx.Err() != nil {
		return &au.Response{
			Status:  408,
			Message: "Context was cancelled",
			Error:   ctx.Err().Error(),
		}, ctx.Err()
	}

	status, err := a.Authentication.SendResetPasswordMail(in.Email)

	if ctx.Err() == context.Canceled {
		cancel()
		return &au.Response{
			Status:  408,
			Message: "Context was cancelled",
			Error:   ctx.Err().Error(),
		}, ctx.Err()
	}

	if err != nil {
		return &au.Response{
			Status:  int32(status),
			Message: "Failed to send reset password mail",
			Error:   err.Error(),
		}, err
	}

	return &au.Response{
		Status:  int32(status),
		Message: "Reset password mail sent successfully",
	}, nil

}

func (a *AuthService) ResetPassword(ctx context.Context, in *au.ResetPasswordRequest) (*au.Response, error) {

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if ctx.Err() != nil {
		return &au.Response{
			Status:  408,
			Message: "Context was cancelled",
			Error:   ctx.Err().Error(),
		}, ctx.Err()
	}

	user := models.User{
		Email:    in.User.Email,
		Username: in.User.Username,
	}

	status, err := a.Authentication.ResetPassword(user, in.NewPassword)

	if ctx.Err() == context.Canceled {
		cancel()
		return &au.Response{
			Status:  408,
			Message: "Context was cancelled",
			Error:   ctx.Err().Error(),
		}, ctx.Err()
	}

	if err != nil {
		return &au.Response{
			Status:  int32(status),
			Message: "Failed to reset password",
			Error:   err.Error(),
		}, err
	}

	return &au.Response{
		Status:  int32(status),
		Message: "Password reset successfully",
	}, nil

}
