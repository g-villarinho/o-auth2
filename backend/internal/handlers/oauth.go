package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/aetheris-lab/aetheris-id/api/internal/domain"
	"github.com/aetheris-lab/aetheris-id/api/internal/middlewares"
	"github.com/aetheris-lab/aetheris-id/api/internal/models"
	"github.com/aetheris-lab/aetheris-id/api/internal/services"
	"github.com/labstack/echo/v4"
)

type OAuthHandler interface {
	Authorize(ectx echo.Context) error
	Token(ectx echo.Context) error
}

type oauthHandler struct {
	oauthService services.OAuthService
}

func NewOAuthHandler(oauthService services.OAuthService) OAuthHandler {
	return &oauthHandler{
		oauthService: oauthService,
	}
}

func (h *oauthHandler) Authorize(ectx echo.Context) error {
	logger := slog.With(
		slog.String("handler", "oauth"),
		slog.String("method", ectx.Request().Method),
		slog.String("path", ectx.Request().URL.Path),
	)

	var payload models.AuthorizePayload
	if err := ectx.Bind(&payload); err != nil {
		logger.Error("failed to bind input", "error", err)
		return echo.ErrBadRequest
	}

	if err := ectx.Validate(payload); err != nil {
		logger.Error("failed to validate payload", "error", err)
		return err
	}

	input := models.NewAuthorizeInput(payload, middlewares.GetUserID(ectx))

	response, err := h.oauthService.Authorize(ectx.Request().Context(), input)
	if err != nil {
		render := func(status int, title, message string) error {
			html := fmt.Sprintf("<html><head><title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>", title, title, message)
			return ectx.HTML(status, html)
		}

		if errors.Is(err, domain.ErrClientNotFound) {
			logger.Warn(err.Error())
			if err := render(http.StatusBadRequest, "Erro de OAuth", "Cliente não encontrado. Verifique o client_id."); err != nil {
				return err
			}
			return echo.ErrBadRequest
		}

		if errors.Is(err, domain.ErrInvalidRedirectURI) {
			logger.Warn(err.Error())
			if err := render(http.StatusBadRequest, "Erro de OAuth", "Redirect URI inválida para o cliente informado."); err != nil {
				return err
			}
			return echo.ErrBadRequest
		}

		if errors.Is(err, domain.ErrInvalidGrantType) || errors.Is(err, domain.ErrInvalidResponseType) {
			logger.Warn(err.Error())
			if err := render(http.StatusBadRequest, "Erro de OAuth", "Parâmetros de autorização inválidos (grant/response type)."); err != nil {
				return err
			}
			return echo.ErrBadRequest
		}

		if errors.Is(err, domain.ErrInvalidScope) {
			logger.Warn(err.Error())
			if err := render(http.StatusBadRequest, "Erro de OAuth", "Um ou mais escopos informados são inválidos para o cliente."); err != nil {
				return err
			}
			return echo.ErrBadRequest
		}

		logger.Error("authorize", "error", err)
		if rErr := render(http.StatusInternalServerError, "Erro interno", "Ocorreu um erro inesperado ao processar a autorização."); rErr != nil {
			return rErr
		}
		return err
	}

	return ectx.Redirect(http.StatusFound, response.RedirectURL)
}

func (h *oauthHandler) Token(ectx echo.Context) error {
	logger := slog.With(
		slog.String("handler", "oauth"),
		slog.String("method", ectx.Request().Method),
		slog.String("path", ectx.Request().URL.Path),
	)

	var payload models.ExchangeAuthorizationCodePayload
	if err := ectx.Bind(&payload); err != nil {
		logger.Error("failed to bind input", "error", err)
		return echo.ErrBadRequest
	}

	if err := ectx.Validate(payload); err != nil {
		logger.Error("failed to validate payload", "error", err)
		return err
	}

	input := models.NewExchangeAuthorizationCodeInput(payload)

	response, err := h.oauthService.ExchangeCodeForToken(ectx.Request().Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrAuthorizationCodeNotFound):
			logger.Warn(err.Error())
			return echo.NewHTTPError(http.StatusBadRequest, "Código de autorização não encontrado ou inválido.")
		case errors.Is(err, domain.ErrAuthorizationCodeExpired):
			logger.Warn(err.Error())
			return echo.NewHTTPError(http.StatusBadRequest, "Código de autorização expirado. Solicite um novo fluxo de autorização.")
		case errors.Is(err, domain.ErrAuthorizationCodeInvalid):
			logger.Warn(err.Error())
			return echo.NewHTTPError(http.StatusBadRequest, "Código de verificação (PKCE) inválido.")
		case errors.Is(err, domain.ErrUnauthorizedClient):
			logger.Warn(err.Error())
			return echo.NewHTTPError(http.StatusUnauthorized, "Cliente não autorizado para este código de autorização.")
		case errors.Is(err, domain.ErrUnauthorizedRedirectURI):
			logger.Warn(err.Error())
			return echo.NewHTTPError(http.StatusUnauthorized, "A redirect_uri informada não corresponde ao código de autorização.")
		case errors.Is(err, domain.ErrClientNotFound):
			logger.Warn(err.Error())
			return echo.NewHTTPError(http.StatusBadRequest, "Cliente associado ao código não foi encontrado.")
		case errors.Is(err, domain.ErrUserNotFound):
			logger.Warn(err.Error())
			return echo.NewHTTPError(http.StatusNotFound, "Usuário associado ao código não foi encontrado.")
		default:
			logger.Error("failed to exchange code for token", "error", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Ocorreu um erro inesperado ao gerar os tokens.")
		}
	}

	return ectx.JSON(http.StatusOK, response)
}
