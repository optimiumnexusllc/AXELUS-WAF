package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"optimiumnexus.com/patronus/axelus-2/management/webserver/api/response"
	"optimiumnexus.com/patronus/axelus-2/management/webserver/model"
	"optimiumnexus.com/patronus/axelus-2/management/webserver/pkg/database"
)

type PostBehaviourRequest struct {
	model.Behaviour
}

func PostBehaviour(c *gin.Context) {
	var params PostBehaviourRequest
	if err := c.BindJSON(&params); err != nil {
		logger.Error(err)
		response.Error(c, response.ErrorParamNotOK, http.StatusInternalServerError)
		return
	}
	db := database.GetDB()
	db.Create(&model.Behaviour{SrcRouter: params.SrcRouter, DstRouter: params.DstRouter})
	response.Success(c, nil)
}
