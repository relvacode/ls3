package exception

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

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
