package router

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"time"

	"github.com/atpons/github-token-proxy/pkg/authn"
	"github.com/atpons/github-token-proxy/pkg/constant"
	"github.com/labstack/echo/v4"
	"golang.org/x/exp/slog"
)

type Request struct {
	RemoteIP  string `json:"remote_ip"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Host      string `json:"host"`
	Status    int    `json:"status"`
	UserAgent string `json:"user_agent"`
	RequestID string `json:"request_id"`
	LatencyMs int    `json:"latency_ms"`
}

func (r *Request) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("remote_ip", r.RemoteIP),
		slog.String("method", r.Method),
		slog.String("url", r.URL),
		slog.String("host", r.Host),
		slog.Int("status", r.Status),
		slog.String("user_agent", r.UserAgent),
		slog.String("request_id", r.RequestID),
		slog.Int("latency_ms", r.LatencyMs),
	)
}

func LoggingMiddleware(logger *slog.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			now := time.Now()
			if err := next(c); err != nil {
				c.Error(err)
			}
			end := time.Now()

			req := c.Request()
			res := c.Response()

			l := &Request{
				RemoteIP:  c.RealIP(),
				Method:    req.Method,
				URL:       req.URL.String(),
				Host:      req.Host,
				Status:    res.Status,
				UserAgent: req.UserAgent(),
				RequestID: GetRequestID(c),
				LatencyMs: int(end.Sub(now).Milliseconds()),
			}

			logger.Info("access", "request", l)
			return nil
		}
	}
}

func AuthenticateMiddleware(authenticator authn.Authenticator) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			res, err := authenticator.Auth(c.Request())
			if err != nil {
				return InternalServerError(err)
			}

			c.Set(constant.AuthResultContextKey, res)

			return next(c)
		}
	}
}

func GetAuthResult(c echo.Context) *authn.Result {
	return c.Get(constant.AuthResultContextKey).(*authn.Result)
}

func RequestIDMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set(echo.HeaderXRequestID, GenerateRequestID())
			return next(c)
		}
	}
}

func GetRequestID(c echo.Context) string {
	reqId := c.Request().Header.Get(echo.HeaderXRequestID)
	if reqId == "" {
		reqId = GenerateRequestID()
		c.Request().Header.Set(echo.HeaderXRequestID, reqId)
	}
	return reqId
}

func GenerateRequestID() string {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		panic(err)
	}
	s := sha1.Sum(buf)
	return hex.EncodeToString(s[:])
}
