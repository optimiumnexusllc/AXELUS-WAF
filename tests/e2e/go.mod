module github.com/optimiumnexusllc/ironwall/tests/e2e

go 1.21

require (
	github.com/gin-gonic/gin v1.10.0
	github.com/optimiumnexusllc/ironwall/licensing v0.0.0
	github.com/optimiumnexusllc/ironwall/geoip v0.0.0
	github.com/optimiumnexusllc/ironwall/premium/zerodayshield v0.0.0
	github.com/optimiumnexusllc/ironwall/premium/ddos v0.0.0
)

replace (
	github.com/optimiumnexusllc/ironwall/licensing => ../../licensing
	github.com/optimiumnexusllc/ironwall/geoip => ../../geoip
	github.com/optimiumnexusllc/ironwall/premium/zerodayshield => ../../premium/zerodayshield
	github.com/optimiumnexusllc/ironwall/premium/ddos => ../../premium/ddos
)
