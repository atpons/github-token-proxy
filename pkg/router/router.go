package router

import (
	"net/http"

	"github.com/atpons/github-token-proxy/pkg/gh"
	"github.com/labstack/echo/v4"
	"golang.org/x/exp/slog"
)

type Handler struct {
	e      *echo.Echo
	authn  *gh.Authenticator
	Logger *slog.Logger
}

func NewHandler(authn *gh.Authenticator, logger *slog.Logger) *Handler {
	e := echo.New()
	h := &Handler{
		e:      e,
		authn:  authn,
		Logger: logger,
	}

	e.GET("/authn", h.HandleAuth)

	return h
}

func (h *Handler) HandleAuth(ctx echo.Context) error {
	owner := ctx.QueryParam("owner")
	repo := ctx.QueryParam("repo")

	t, err := h.authn.GetToken(owner, repo)

	if err != nil {
		h.Logger.Error("err", err)
		return ctx.NoContent(http.StatusInternalServerError)
	}

	return ctx.JSON(http.StatusOK, echo.Map{"token": t})
}

func (h *Handler) Start() error {
	h.Logger.Info("listening...")
	return h.e.Start(":8080")
}
