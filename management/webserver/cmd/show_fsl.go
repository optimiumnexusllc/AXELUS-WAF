package cmd

import (
	"optimiumnexus.com/patronus/ironwall-2/management/webserver/pkg/database"
	"optimiumnexus.com/patronus/ironwall-2/management/webserver/pkg/fvm"
)

func ShowFSL() (string, error) {
	return fvm.GenerateFullFSL(database.GetDB().DB)
}
