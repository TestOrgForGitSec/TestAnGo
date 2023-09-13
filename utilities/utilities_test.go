package utilities

import (
	"context"
	"testing"

	"github.com/cloudbees-compliance/chlog-go/log"
	"github.com/stretchr/testify/assert"
)

func TestGetRequestId(t *testing.T) {
	log.Debug().Msg("Inside TestGetRequestId - Enter")

	res := GetRequestId(context.Background())
	assert.Empty(t, res)

	var contextValue context.Context
	res = GetRequestId(contextValue)
	assert.Empty(t, res)
	log.Debug().Msg("Inside TestGetRequestId - Exit")
}

func TestGetValidURL(t *testing.T) {
	log.Debug().Msg("Inside TestGetValidURL - Enter")

	res := GetValidURL("anchore.sample.com//")
	assert.Equal(t, "https://anchore.sample.com", res)

	log.Debug().Msg("Inside TestGetValidURL - Exit")
}
