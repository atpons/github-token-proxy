package router

import (
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/labstack/echo/v4"
	"golang.org/x/exp/slog"
)

type ErrorCode string

const (
	ErrorCodeInternal ErrorCode = "internal_error"
)

var (
	ResponseCodeToErrorCode = map[int]ErrorCode{
		http.StatusInternalServerError: ErrorCodeInternal,
	}
)

type Error struct {
	Message   string    `json:"message"`
	ErrorCode ErrorCode `json:"error_code"`
	Err       error     `json:",omitempty"`
}

func (e *Error) Error() string {
	return e.Message
}

type InternalError struct {
	Err error
}

func (e *InternalError) Error() string {
	return e.Err.Error()
}

func (e *InternalError) Unwrap() error {
	return e.Err
}

func InternalServerError(err error) *InternalError {
	return &InternalError{
		Err: err,
	}
}

func HTTPErrorHandler(logger *slog.Logger) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		var status = http.StatusInternalServerError
		errorMap := &Error{
			Message:   "unknown error",
			ErrorCode: ErrorCodeInternal,
		}

		switch e := err.(type) {
		case *echo.HTTPError:
			switch m := e.Message.(type) {
			case error:
				errorMap.Message = m.Error()
			default:
				errorMap.Message = e.Error()
			}
			if c, ok := ResponseCodeToErrorCode[e.Code]; ok {
				errorMap.ErrorCode = c
			}
		case *Error:
			logger.Error("server error",
				slog.String("error_description", e.Error()),
				slog.String("error_details", e.Err.Error()),
			)
			errorMap = e
		case *InternalError:
			d := errors.GetAllSafeDetails(e.Err)
			var last string
			if len(d) > 0 {
				l := d[len(d)-1].SafeDetails[0]
				last = l
			}
			logger.Error("internal server error",
				slog.String("error_description", e.Error()),
				slog.String("error_details", e.Err.Error()),
				slog.String("last_stack", last),
			)
		}

		c.JSON(status, errorMap)
	}
}
