package model

import (
	"bytes"
	"encoding/json"
	"net/http"

	"gorm.io/gorm/clause"

	"optimiumnexus.com/patronus/ironwall-2/management/webserver/pkg/config"

	"optimiumnexus.com/patronus/ironwall-2/management/webserver/pkg"
	"optimiumnexus.com/patronus/ironwall-2/management/webserver/pkg/constants"
	"optimiumnexus.com/patronus/ironwall-2/management/webserver/pkg/database"
	"optimiumnexus.com/patronus/ironwall-2/management/webserver/utils"
)

type Options struct {
	Base
	Key   string `gorm:"column:key;uniqueIndex"`
	Value string `gorm:"column:value;"`
}

func initOptions() error {
	db := database.GetDB()

	secretKey := Options{Key: constants.SecretKey, Value: utils.RandStr(32)}
	db.Clauses(clause.OnConflict{DoNothing: true}).Create(&secretKey)

	machineId := Options{Key: constants.MachineID, Value: utils.RandStr(32)}
	_ = db.Clauses(clause.OnConflict{DoNothing: true}).Create(&machineId)
	go NotifyInstallation(machineId.Value)

	return nil
}

func NotifyInstallation(machineId string) {
	logger.Info("Notify installation")
	tr := pkg.TelemetryRequest{
		Telemetry: pkg.TelemetryInfo{
			Id: constants.TelemetryId,
		},
		Safeline: pkg.SafelineInfo{
			Id:      machineId,
			Type:    constants.Installation,
			Version: constants.Version,
		},
	}
	data, err := json.Marshal(tr)
	if err != nil {
		logger.Error(err)
		return
	}

	reader := bytes.NewReader(data)
	rsp, err := pkg.DoPostTelemetry(utils.GetHTTPClient(), config.GlobalConfig.Telemetry.Addr, reader)
	if err != nil {
		logger.Error(err)
		return
	}

	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != http.StatusCreated {
		logger.Errorf("transfer telemetry %s failed, status code = %d", constants.Installation, rsp.StatusCode)
		return
	}
}
