package app

import "github.com/gin-gonic/gin"

func (s *Server) Routes() *gin.Engine {
	router := s.router

	// group all routes under /v1/api
	v1 := router.Group("/columbia")
	{
		v1.GET("/:id", s.Query())
	}

	v2 := router.Group("/api_test_sub")
	{
		v2.GET("/:id", s.Query())
	}

	v3 := router.Group("/api_test_obj")
	{
		v3.GET("/:id", s.QueryObj())
	}

	v4 := router.Group("/reorder_test")
	{
		v4.GET("/:count", s.ReorderTest())
	}

	return router
}
