package prometheus

import (
	"github.com/Symantec/tricorder/go/tricorder"
	"github.com/Symantec/tricorder/go/tricorder/units"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

var (
	metricsMutex                 = &sync.Mutex{}
	externalServiceDurationTotal = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "smallpoint_external_service_request_duration",
			Help:    "Total amount of time spent non-errored external checks in ms",
			Buckets: []float64{5, 7.5, 10, 15, 25, 50, 75, 100, 150, 250, 500, 750, 1000, 1500, 2500, 5000},
		},
		[]string{"service_name"},
	)
	tricorderLDAPExternalServiceDurationTotal    = tricorder.NewGeometricBucketer(5, 5000.0).NewCumulativeDistribution()
	tricorderStorageExternalServiceDurationTotal = tricorder.NewGeometricBucketer(1, 2000.0).NewCumulativeDistribution()
)

func init() {
	prometheus.MustRegister(externalServiceDurationTotal)
	tricorder.RegisterMetric(
		"keymaster/external-service-duration/LDAP",
		tricorderLDAPExternalServiceDurationTotal,
		units.Millisecond,
		"Time for external LDAP server to perform operation(ms)")
	tricorder.RegisterMetric(
		"keymaster/external-service-duration/storage",
		tricorderStorageExternalServiceDurationTotal,
		units.Millisecond,
		"Time for external Storage server to perform operation(ms)")
}

func MetricLogExternalServiceDuration(service string, duration time.Duration) {
	val := duration.Seconds() * 1000
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	externalServiceDurationTotal.WithLabelValues(service).Observe(val)
	switch service {
	case "ldap":
		tricorderLDAPExternalServiceDurationTotal.Add(duration)
	case "storage":
		tricorderStorageExternalServiceDurationTotal.Add(duration)
	}
}
