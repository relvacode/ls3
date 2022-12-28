package ls3

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	StatRegistry = prometheus.NewRegistry()

	statApiPolicyDenials = promauto.With(StatRegistry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "ApiPolicyDenials",
			Help: "Total count of policy denied API calls",
		},
		[]string{
			"operation",
			"resource",
			"identity",
			"remote_addr",
		},
	)
	statApiCall = promauto.With(StatRegistry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "ApiOperation",
			Help: "Total count of policy permitted API calls",
		},
		[]string{
			"operation",
			"resource",
			"identity",
			"remote_addr",
		},
	)
	statBytesTransferredOut = promauto.With(StatRegistry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "BytesTransferredOut",
			Help: "Number of bytes transferred out by GetObject",
		},
		[]string{
			"bucket",
			"object",
			"identity",
			"remote_addr",
		},
	)
)
