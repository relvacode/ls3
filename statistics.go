package ls3

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	StatRegistry = prometheus.NewRegistry()

	statApiError = promauto.With(StatRegistry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ls3",
			Subsystem: "api",
			Name:      "error",
			Help:      "Total count of API errors by error code",
		},
		[]string{
			"identity",
			"client_ip",
			"error_code",
		},
	)
	statApiPolicyDenials = promauto.With(StatRegistry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ls3",
			Subsystem: "api",
			Name:      "policy_denials",
			Help:      "Total count of policy denied API calls",
		},
		[]string{
			"operation",
			"resource",
			"identity",
			"client_ip",
		},
	)
	statApiCall = promauto.With(StatRegistry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ls3",
			Subsystem: "api",
			Name:      "operations",
			Help:      "Total count of policy permitted API calls",
		},
		[]string{
			"operation",
			"resource",
			"identity",
			"client_ip",
		},
	)
	statBytesTransferredOut = promauto.With(StatRegistry).NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ls3",
			Name:      "bytes_transferred_out",
			Help:      "Number of bytes transferred out by GetObject",
		},
		[]string{
			"bucket",
			"object",
			"identity",
			"client_ip",
		},
	)
)
