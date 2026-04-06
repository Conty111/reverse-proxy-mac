package ldap

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const metricsNamespace = "mac_authserver"
const metricsSubsystem = "ldap"

var (
	// ldapConnectionUp indicates whether the LDAP connection is currently active (1) or down (0).
	ldapConnectionUp = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "connection_up",
		Help:      "Whether the LDAP connection is currently active (1 = up, 0 = down).",
	})

	// ldapConnectionsTotal counts the total number of LDAP connection attempts, partitioned by outcome.
	ldapConnectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "connections_total",
		Help:      "Total number of LDAP connection attempts.",
	}, []string{"status"}) // status: "success" | "error"

	// ldapReconnectsTotal counts the total number of LDAP reconnection attempts.
	ldapReconnectsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "reconnects_total",
		Help:      "Total number of LDAP reconnection attempts.",
	}, []string{"status"}) // status: "success" | "error"

	// ldapSearchDuration observes the duration of LDAP search operations in seconds.
	ldapSearchDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "search_duration_seconds",
		Help:      "Duration of LDAP search operations in seconds.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	})

	// ldapSearchTotal counts the total number of LDAP search operations, partitioned by outcome.
	ldapSearchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "search_total",
		Help:      "Total number of LDAP search operations.",
	}, []string{"status"}) // status: "success" | "error"
)
