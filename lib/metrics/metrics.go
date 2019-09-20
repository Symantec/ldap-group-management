package metrics

import (
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
)

func init() {
	prometheus.MustRegister(externalServiceDurationTotal)
}

func MetricLogExternalServiceDuration(service string, duration time.Duration) {
	val := duration.Seconds() * 1000
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	externalServiceDurationTotal.WithLabelValues(service).Observe(val)
}
