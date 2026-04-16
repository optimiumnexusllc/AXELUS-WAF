module github.com/optimiumnexusllc/axelus/tests/e2e

go 1.21

require (
	github.com/gin-gonic/gin v1.10.0
	github.com/optimiumnexusllc/axelus/licensing v0.0.0
	github.com/optimiumnexusllc/axelus/geoip v0.0.0
	github.com/optimiumnexusllc/axelus/premium/zerodayshield v0.0.0
	github.com/optimiumnexusllc/axelus/premium/ddos v0.0.0
)

replace (
	github.com/optimiumnexusllc/axelus/licensing => ../../licensing
	github.com/optimiumnexusllc/axelus/geoip => ../../geoip
	github.com/optimiumnexusllc/axelus/premium/zerodayshield => ../../premium/zerodayshield
	github.com/optimiumnexusllc/axelus/premium/ddos => ../../premium/ddos
)
