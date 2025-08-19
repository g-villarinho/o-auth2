package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/aetheris-lab/aetheris-id/api/internal/domain"
	"github.com/aetheris-lab/aetheris-id/api/internal/middlewares"
	"github.com/aetheris-lab/aetheris-id/api/internal/models"
	"github.com/aetheris-lab/aetheris-id/api/internal/services"
	"github.com/labstack/echo/v4"
)

type AuthHandler interface {
	Login(ectx echo.Context) error
	Authenticate(ectx echo.Context) error
	ResendVerificationCode(ectx echo.Context) error
	Register(ectx echo.Context) error
}

type authHandler struct {
	authService      services.AuthService
	cookieMiddleware middlewares.CookieMiddleware
}

func NewAuthHandler(
	authService services.AuthService,
	cookieMiddleware middlewares.CookieMiddleware,
) AuthHandler {
	return &authHandler{
		authService:      authService,
		cookieMiddleware: cookieMiddleware,
	}
}

func (h *authHandler) Login(ectx echo.Context) error {
	logger := slog.With(
		slog.String("handler", "auth"),
		slog.String("method", "login"),
	)

	var payload models.LoginPayload
	if err := ectx.Bind(&payload); err != nil {
		logger.Error("bind payload", "error", err)
		return echo.ErrBadRequest
	}

	if err := ectx.Validate(payload); err != nil {
		logger.Error("validate payload", "error", err)
		return err
	}

	response, err := h.authService.SendVerificationCode(ectx.Request().Context(), payload.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Error(err.Error())
			return echo.ErrNotFound
		}

		logger.Error("send verification code", "error", err)
		return echo.ErrInternalServerError
	}

	maxAge := int(response.ExpiresAt.Sub(time.Now().UTC()).Seconds())
	h.cookieMiddleware.SetCookie(ectx, response.OTPToken, maxAge)

	return ectx.JSON(http.StatusOK, response)
}

func (h *authHandler) Authenticate(ectx echo.Context) error {
	logger := slog.With(
		slog.String("handler", "auth"),
		slog.String("method", "authenticate"),
	)

	var payload models.AuthenticatePayload
	if err := ectx.Bind(&payload); err != nil {
		logger.Error("bind payload", "error", err)
		return echo.ErrBadRequest
	}

	if err := ectx.Validate(payload); err != nil {
		logger.Error("validate payload", "error", err)
		return err
	}

	otpID := middlewares.GetOTPJTI(ectx)
	if otpID == "" {
		logger.Error("otp id not found")
		return echo.ErrUnauthorized
	}

	response, err := h.authService.Authenticate(ectx.Request().Context(), payload.Code, otpID)
	if err != nil {
		if errors.Is(err, domain.ErrOTPNotFound) {
			logger.Error(err.Error())
			return echo.ErrUnauthorized
		}

		if errors.Is(err, domain.ErrInvalidCode) {
			logger.Error(err.Error())
			return echo.ErrUnauthorized
		}

		if errors.Is(err, domain.ErrOTPExpired) {
			logger.Error(err.Error())
			return echo.ErrUnauthorized
		}

		logger.Error("authenticate", "error", err)
		return echo.ErrInternalServerError
	}

	maxAge := int(response.ExpiresAt.Sub(time.Now().UTC()).Seconds())
	h.cookieMiddleware.SetCookie(ectx, response.AccessToken, maxAge)

	return ectx.JSON(http.StatusOK, response)
}

func (h *authHandler) ResendVerificationCode(ectx echo.Context) error {
	logger := slog.With(
		slog.String("handler", "auth"),
		slog.String("method", "resend verification code"),
	)

	otpID := middlewares.GetOTPJTI(ectx)
	if otpID == "" {
		logger.Error("otp id not found")
		return echo.ErrUnauthorized
	}

	err := h.authService.ResendVerificationCode(ectx.Request().Context(), otpID)
	if err != nil {
		var errOTPNotResendable *domain.ErrOTPNotResendable
		if errors.As(err, &errOTPNotResendable) {
			remainingSeconds := int(math.Ceil(errOTPNotResendable.TimeRemaining.Seconds()))

			ectx.Response().Header().Set("Retry-After", fmt.Sprintf("%d", remainingSeconds))
			logger.Error(err.Error())
			return echo.ErrTooManyRequests
		}

		if errors.Is(err, domain.ErrOTPNotFound) {
			logger.Error(err.Error())
			return echo.ErrUnauthorized
		}

		logger.Error("resend verification code", "error", err)
		return echo.ErrInternalServerError
	}

	return ectx.NoContent(http.StatusNoContent)
}

func (h *authHandler) Register(ectx echo.Context) error {
	logger := slog.With(
		slog.String("handler", "auth"),
		slog.String("method", "register"),
	)

	var payload models.RegisterPayload
	if err := ectx.Bind(&payload); err != nil {
		logger.Error("bind payload", "error", err)
		return echo.ErrBadRequest
	}

	if err := ectx.Validate(payload); err != nil {
		logger.Error("validate payload", "error", err)
		return err
	}

	response, err := h.authService.Register(ectx.Request().Context(), payload.FirstName, payload.LastName, payload.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserAlreadyRegistered) {
			logger.Error(err.Error())
			return echo.ErrBadRequest
		}

		logger.Error("register", "error", err)
		return echo.ErrInternalServerError
	}

	maxAge := int(response.ExpiresAt.Sub(time.Now().UTC()).Seconds())
	h.cookieMiddleware.SetCookie(ectx, response.OTPToken, maxAge)

	return ectx.JSON(http.StatusOK, response)
}
