package ls3

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func assertIsError(t *testing.T, err error, code ErrorCode) {
	ec, ok := err.(*Error)
	assert.True(t, ok, "Expected error to be an *Error")

	assert.Equal(t, code, ec.ErrorCode)
}
