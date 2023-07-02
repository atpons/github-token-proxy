package router

import (
	"context"
	"net/http"
	"time"

	"github.com/atpons/github-token-proxy/pkg/authn"
	"github.com/atpons/github-token-proxy/pkg/constant"
	"github.com/atpons/github-token-proxy/pkg/gh"
	"github.com/labstack/echo/v4"
	"golang.org/x/exp/slog"
)

type Handler struct {
	e             *echo.Echo
	authenticator authn.Authenticator
	client        *gh.Client
	Logger        *slog.Logger
}

func NewHandler(client *gh.Client, authenticator authn.Authenticator, logger *slog.Logger) *Handler {
	e := echo.New()

	e.HidePort = true
	e.HideBanner = true

	e.Use(LoggingMiddleware(logger))
	e.Use(AuthenticateMiddleware(authenticator))
	e.Use(RequestIDMiddleware())

	e.HTTPErrorHandler = HTTPErrorHandler(logger)
	h := &Handler{
		e:      e,
		client: client,
		Logger: logger,
	}

	e.GET("/client", h.HandleAuth)

	return h
}

func (h *Handler) HandleAuth(ctx echo.Context) error {
	owner := ctx.QueryParam("owner")
	repo := ctx.QueryParam("repo")

	rctx := context.WithValue(ctx.Request().Context(), constant.RequestIdContextKey, GetRequestID(ctx))

	t, err := h.client.GetToken(rctx, owner, repo)

	discoverableHash := gh.ConvertTokenToDiscoverableHash(t)

	ares := GetAuthResult(ctx)

	h.Logger.Info("token generated",
		slog.String("requester_hostname", ares.Requester),
		slog.String("discoverable_hash", discoverableHash),
		slog.Time("requested_at", time.Now()),
	)

	if err != nil {
		return InternalServerError(err)
	}

	return ctx.JSON(http.StatusOK, echo.Map{"token": t})
}

func (h *Handler) Start() error {
	h.Logger.Info("listening...")
	return h.e.Start(":8080")
}
