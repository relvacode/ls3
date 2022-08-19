package ls3

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func assertIsError(t *testing.T, err error, code ErrorCode) {
	assert.NotNil(t, err, "Expected an error")
	assert.True(t, errors.Is(err, &Error{
		ErrorCode: code,
	}))
}

func TestError_Is(t *testing.T) {
	wrapped := fmt.Errorf("wrapped: %w", &Error{
		ErrorCode: InternalError,
		Message:   "A wrapped error",
	})

	test := &Error{
		ErrorCode: InternalError,
		Message:   "An error with a different message",
	}

	assert.True(t, errors.Is(wrapped, test))
}
