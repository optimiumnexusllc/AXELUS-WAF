package model

import (
	"gorm.io/gorm/clause"

	"optimiumnexus.com/patronus/axelus-2/management/webserver/pkg/constants"
	"optimiumnexus.com/patronus/axelus-2/management/webserver/pkg/database"
)

type User struct {
	Base
	Username string `gorm:"uniqueIndex;not null"`
	Password string
	Comment  string

	TFAEnabled    bool   `gorm:"column:tfa_enabled;default:true"`
	TFASecret     string `gorm:"column:tfa_secret"`
	LastLoginTime int64  `gorm:"default:0"`
	IsEnabled     bool   `gorm:"default:true"`
}

func initAdminUser() error {
	db := database.GetDB()
	user := User{
		Username: constants.SuperUser,
	}
	db.Clauses(clause.OnConflict{DoNothing: true}).Create(&user)
	return nil
}
