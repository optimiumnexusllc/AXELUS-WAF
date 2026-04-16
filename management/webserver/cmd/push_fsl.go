package cmd

import (
	"optimiumnexus.com/patronus/axelus-2/management/webserver/pkg/database"
	"optimiumnexus.com/patronus/axelus-2/management/webserver/pkg/fvm"
)

func PushFSL() error {
	return fvm.PushFSL(database.GetDB().DB)
}
