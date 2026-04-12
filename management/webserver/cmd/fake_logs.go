package cmd

import "optimiumnexus.com/patronus/ironwall-2/management/webserver/model"

func FakeLogs() {
	model.InitDetectLogSamples()
}
