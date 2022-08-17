package ls3

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func assertIsError(t *testing.T, err error, code ErrorCode) {
	assert.NotNil(t, err, "Expected an error")

	ec, ok := err.(*Error)
	assert.True(t, ok, "Expected error to be an *Error")
	if ok {
		assert.Equal(t, code, ec.ErrorCode)
	}

}
