package app

import (
	sqlctx "context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	jwt "github.com/golang-jwt/jwt/v4"
)

type UserAttrs struct {
	User_id string
	Attrs   string
}

type DevAttrs struct {
	Dev_id string
	Attrs  string
}

type DBAccess struct {
	User_id        string `json:"user_id"`
	Table_name     string `json:"table_name"`
	Db_access_date string `json:"db_access_date"`
	Db_deny_date   string `json:"db_deny_date"`
}

type JWTRequest struct {
	ClientMessage string `json:"client_message"`
}

type Policy struct {
	Ref     string
	Content string
}

type Hierarchy struct {
	Obj_id    string
	Action    string
	Hierarchy string
}

type UserCheckInfo struct {
	User_id  string
	Password string
}

type DevCheckInfo struct {
	Dev_id   string
	Dev_type string
	Token    string
	Attrs    string
}

type DevActions struct {
	Dev_id  string
	Actions string
}

type InsertPolicyRequest struct {
	Ref     string `json: "ref"`
	Content string `json: "policy_content"`
}

type UpdatePolicyRequest struct {
	Ref     string `json: "ref"`
	Content string `json: "policy_content"`
}

type InsertPermInfoQueryRequest struct {
	User_id        string `json: "user_id"`
	Tbl_name       string `json: "tbl_name"`
	Db_access_date string `json: "db_access_date"`
	Db_deny_date   string `json: "db_deny_date"`
}

type UpdateSecureDBAllowRequest struct {
	User_id        string `json: "user_id"`
	Tbl_name       string `json: "tbl_name"`
	Db_access_date string `json: "db_access_date"`
}

type UpdateSecureDBDenyRequest struct {
	User_id      string `json: "user_id"`
	Tbl_name     string `json: "tbl_name"`
	Db_deny_date string `json: "db_deny_date"`
}

const (
	FindPolicyQuery            = "SELECT ref, content FROM rego_policy_repository WHERE ref=? LIMIT 1"
	InsertPolicyQuery          = "INSERT INTO rego_policy_repository(ref, content) VALUES(?, ?)" //use generated keys?
	UpdatePolicyQuery          = "UPDATE rego_policy_repository SET content=#{pojo.content} WHERE ref=#{pojo.ref}"
	FindHierarchyQuery         = "SELECT obj_id, action, hierarchy FROM object_action_policy_hierarchy WHERE obj_id=? AND action=? LIMIT 1"
	InsertObjectHierarchyQuery = "INSERT INTO object_action_policy_hierarchy(obj_id, action, hierarchy) VALUES(#{objId}, #{action}, #{hierarchy})"
	UpdateObjectHierarchyQuery = "UPDATE object_action_policy_hierarchy SET hierarchy=#{pojo.hierarchy} WHERE obj_id=#{pojo.objId} AND " + "action=#{pojo.action}"
	FindUserAttrsQuery         = "SELECT user_id, attrs FROM user_attrs WHERE user_id=? LIMIT 1"
	InsertUserAttrsQuery       = "INSERT INTO user_attrs(user_id, pwd, attrs) VALUES(#{userId}, #{password}, #{attrs})"
	UpdateUserAttrsQuery       = "UPDATE user_attrs SET attrs=#{pojo.attrs} WHERE user_id=#{pojo.userId}"
	FindUserCheckInfoQuery     = "SELECT user_id, pwd FROM user_attrs WHERE user_id=? LIMIT 1"
	FindDevCheckInfoQuery      = "SELECT dev_id, dev_type, token FROM dev_info WHERE dev_id=? LIMIT 1"
	InsertDevInfoQuery         = "INSERT INTO dev_info(dev_id, dev_type, token, attrs) VALUES(#{devId}, #{devType}, #{token}, #{attrs})"
	FindDevActionsQuery        = "SELECT dev_id, actions FROM dev_info WHERE dev_id=? LIMIT 1"
	FindDevAttrsQuery          = "SELECT dev_id, attrs FROM dev_info WHERE dev_id=? LIMIT 1"
	InsertDevInfoFullQuery     = "INSERT INTO dev_info(dev_id, dev_type, actions, token, attrs) VALUES(#{devId}, #{devType}, #{actions}, " + "#{token}, #{attrs})"
	InsertPermInfoQuery        = "INSERT INTO db_access(user_id, tbl_name, db_access_date, db_deny_date) VALUES(?, ?, ?, ?)"
	FindAccessDateQuery        = "SELECT user_id, tbl_name, db_access_date, db_deny_date FROM db_access WHERE user_id=? AND tbl_name=? LIMIT 1"
	UpdateSecureDBAllowQuery   = "UPDATE db_access SET db_access_date=? WHERE user_id=? AND tbl_name=? "
	UpdateSecureDBDenyQuery    = "UPDATE db_access SET db_deny_date=#{pojo.denyDate} WHERE user_id=#{pojo.userId} AND tbl_name=#{pojo.tableName}"
)

func (s *Server) FindUserAttrs() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		id := context.Param("id")

		res, err := s.conn.Query(FindUserAttrsQuery, id)
		fmt.Printf("query temp: %v, params: %v\n", FindUserAttrsQuery, id)

		if err != nil {
			fmt.Printf("Unable to execute sql_query, template: %v, params: %v, err: %v\n",
				FindUserAttrsQuery, id, err)
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		defer func(res *sql.Rows) {
			err := res.Close()
			if err != nil {
				fmt.Printf("close res err: %v\n", err)
			}
		}(res)

		var result UserAttrs

		if res.Next() {
			if err := res.Scan(&result.User_id, &result.Attrs); err != nil {
				fmt.Printf("scan err: %v\n", err)
				context.JSON(http.StatusBadRequest, nil)
				return
			}
		} else {
			fmt.Printf("empty query result\n")
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		fmt.Printf("attrs: %+v\n", result.Attrs)

		time.Sleep(100 * time.Millisecond)

		ret, err := json.Marshal(result)
		if err != nil {
			fmt.Println(err)
			return
		}
		context.String(http.StatusOK, string(ret))
	}
}

func (s *Server) FindPolicy() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		ref := context.Param("ref")
		res, err := s.conn.Query(FindPolicyQuery, ref)
		fmt.Printf("query temp: %v, params: %v\n", FindPolicyQuery, ref)

		if err != nil {
			fmt.Printf("Unable to execute sql_query, template: %v, params: %v, err: %v\n",
				FindPolicyQuery, ref, err)
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		defer func(res *sql.Rows) {
			err := res.Close()
			if err != nil {
				fmt.Printf("close res err: %v\n", err)
			}
		}(res)

		var result Policy

		if res.Next() {
			if err := res.Scan(&result.Ref, &result.Content); err != nil {
				fmt.Printf("scan err: %v\n", err)
				context.JSON(http.StatusBadRequest, nil)
				return
			}
		} else {
			fmt.Printf("empty query result\n")
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		fmt.Printf("policy: %+v\n", result)

		time.Sleep(100 * time.Millisecond)

		ret, err := json.Marshal(result)
		if err != nil {
			fmt.Println(err)
			return
		}
		context.String(http.StatusOK, string(ret))
	}
}

func (s *Server) FindHierarchy() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		obj_id := context.Param("obj_id")
		action := context.Param("action")
		res, err := s.conn.Query(FindHierarchyQuery, obj_id, action)
		fmt.Printf("query temp: %v, params: %v, %v\n", FindHierarchyQuery, obj_id, action)

		if err != nil {
			fmt.Printf("Unable to execute sql_query, template: %v, params: %v, %v, err: %v\n",
				FindHierarchyQuery, obj_id, action, err)
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		defer func(res *sql.Rows) {
			err := res.Close()
			if err != nil {
				fmt.Printf("close res err: %v\n", err)
			}
		}(res)

		var result Hierarchy

		if res.Next() {
			if err := res.Scan(&result.Obj_id, &result.Action, &result.Hierarchy); err != nil {
				fmt.Printf("scan err: %v\n", err)
				context.JSON(http.StatusBadRequest, nil)
				return
			}
		} else {
			fmt.Printf("empty query result\n")
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		fmt.Printf("hierarchy: %+v\n", result)

		time.Sleep(100 * time.Millisecond)

		ret, err := json.Marshal(result)
		if err != nil {
			fmt.Println(err)
			return
		}
		context.String(http.StatusOK, string(ret))
	}
}

func (s *Server) FindUserCheckInfo() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		user_id := context.Param("user_id")
		res, err := s.conn.Query(FindUserCheckInfoQuery, user_id)
		fmt.Printf("query temp: %v, params: %v \n", FindUserCheckInfoQuery, user_id)

		if err != nil {
			fmt.Printf("Unable to execute sql_query, template: %v, params: %v, err: %v\n",
				FindUserCheckInfoQuery, user_id, err)
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		defer func(res *sql.Rows) {
			err := res.Close()
			if err != nil {
				fmt.Printf("close res err: %v\n", err)
			}
		}(res)

		var result UserCheckInfo

		if res.Next() {
			if err := res.Scan(&result.User_id, &result.Password); err != nil {
				fmt.Printf("scan err: %v\n", err)
				context.JSON(http.StatusBadRequest, nil)
				return
			}
		} else {
			fmt.Printf("empty query result\n")
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		fmt.Printf("hierarchy: %+v\n", result)

		time.Sleep(100 * time.Millisecond)

		ret, err := json.Marshal(result)
		if err != nil {
			fmt.Println(err)
			return
		}
		context.String(http.StatusOK, string(ret))
	}
}

func (s *Server) FindDevCheckInfo() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		dev_id := context.Param("dev_id")
		res, err := s.conn.Query(FindDevCheckInfoQuery, dev_id)
		fmt.Printf("query temp: %v, params: %v \n", FindDevCheckInfoQuery, dev_id)

		if err != nil {
			fmt.Printf("Unable to execute sql_query, template: %v, params: %v, err: %v\n",
				FindDevCheckInfoQuery, dev_id, err)
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		defer func(res *sql.Rows) {
			err := res.Close()
			if err != nil {
				fmt.Printf("close res err: %v\n", err)
			}
		}(res)

		var result DevCheckInfo

		if res.Next() {
			if err := res.Scan(&result.Dev_id, &result.Dev_type, &result.Token); err != nil {
				fmt.Printf("scan err: %v\n", err)
				context.JSON(http.StatusBadRequest, nil)
				return
			}
		} else {
			fmt.Printf("empty query result\n")
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		fmt.Printf("hierarchy: %+v\n", result)

		time.Sleep(100 * time.Millisecond)

		ret, err := json.Marshal(result)
		if err != nil {
			fmt.Println(err)
			return
		}
		context.String(http.StatusOK, string(ret))
	}
}

func (s *Server) FindDevAttrs() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		dev_id := context.Param("dev_id")

		res, err := s.conn.Query(FindDevAttrsQuery, dev_id)
		fmt.Printf("query temp: %v, params: %v\n", FindUserAttrsQuery, dev_id)

		if err != nil {
			fmt.Printf("Unable to execute sql_query, template: %v, params: %v, err: %v\n",
				FindDevAttrsQuery, dev_id, err)
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		defer func(res *sql.Rows) {
			err := res.Close()
			if err != nil {
				fmt.Printf("close res err: %v\n", err)
			}
		}(res)

		var result DevAttrs

		if res.Next() {
			if err := res.Scan(&result.Dev_id, &result.Attrs); err != nil {
				fmt.Printf("scan err: %v\n", err)
				context.JSON(http.StatusBadRequest, nil)
				return
			}
		} else {
			fmt.Printf("empty query result\n")
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		fmt.Printf("attrs: %+v\n", result)

		time.Sleep(100 * time.Millisecond)

		ret, err := json.Marshal(result)
		if err != nil {
			fmt.Println(err)
			return
		}
		context.String(http.StatusOK, string(ret))
	}
}

func (s *Server) FindDevActions() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		dev_id := context.Param("dev_id")

		res, err := s.conn.Query(FindDevActionsQuery, dev_id)
		fmt.Printf("query temp: %v, params: %v\n", FindDevActionsQuery, dev_id)

		if err != nil {
			fmt.Printf("Unable to execute sql_query, template: %v, params: %v, err: %v\n",
				FindDevActionsQuery, dev_id, err)
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		defer func(res *sql.Rows) {
			err := res.Close()
			if err != nil {
				fmt.Printf("close res err: %v\n", err)
			}
		}(res)

		var result DevActions

		if res.Next() {
			if err := res.Scan(&result.Dev_id, &result.Actions); err != nil {
				fmt.Printf("scan err: %v\n", err)
				context.JSON(http.StatusBadRequest, nil)
				return
			}
		} else {
			fmt.Printf("empty query result\n")
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		fmt.Printf("actions: %+v\n", result)

		time.Sleep(100 * time.Millisecond)

		ret, err := json.Marshal(result)
		if err != nil {
			fmt.Println(err)
			return
		}
		context.String(http.StatusOK, string(ret))
	}
}

func (s *Server) FindDBAccess() gin.HandlerFunc {
	fmt.Println("here find db access")
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		user_id := context.Param("user_id")
		table_name := context.Param("table_name")

		res, err := s.conn.Query(FindAccessDateQuery, user_id, table_name)
		fmt.Printf("query temp: %v, params: %v, %v\n", FindAccessDateQuery, user_id, table_name)

		if err != nil {
			fmt.Printf("Unable to execute sql_query, template: %v, params: %v, %v, err: %v\n",
				FindAccessDateQuery, user_id, table_name, err)
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		defer func(res *sql.Rows) {
			err := res.Close()
			if err != nil {
				fmt.Printf("close res err: %v\n", err)
			}
		}(res)

		var result DBAccess

		if res.Next() {
			if err := res.Scan(&result.User_id, &result.Table_name, &result.Db_access_date, &result.Db_deny_date); err != nil {
				fmt.Printf("scan err: %v\n", err)
				context.JSON(http.StatusBadRequest, nil)
				return
			}
		} else {
			fmt.Printf("empty query result\n")
			context.JSON(http.StatusBadRequest, nil)
			return
		}

		fmt.Printf("actions: %+v\n", result)

		time.Sleep(100 * time.Millisecond)

		ret, err := json.Marshal(result)
		if err != nil {
			fmt.Println(err)
			return
		}
		context.String(http.StatusOK, string(ret))
	}
}

func (s *Server) InsertPolicy() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		ref := context.Param("ref")
		reqBody, err := ioutil.ReadAll(context.Request.Body)

		var reqdata InsertPolicyRequest
		json.Unmarshal(reqBody, &reqdata)
		ctx, cancelfunc := sqlctx.WithTimeout(sqlctx.Background(), 5*time.Second)
		defer cancelfunc()
		stmt, err := s.conn.PrepareContext(ctx, InsertPolicyQuery)
		if err != nil {
			fmt.Printf("Error %s when preparing SQL statement", err)
			return
		}

		defer stmt.Close()
		res, err := stmt.ExecContext(ctx, ref, reqdata.Content)
		if err != nil {
			fmt.Printf("Error %s when inserting row into products table", err)
			return
		}
		rows, err := res.RowsAffected()
		if err != nil {
			fmt.Printf("Error %s when finding rows affected", err)
			return
		}

		log.Printf("%d rows inserted ", rows)

		context.String(http.StatusOK, string(rows)+" rows inserted ")
	}
}

func (s *Server) UpdatePolicy() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		ref := context.Param("ref")
		reqBody, err := ioutil.ReadAll(context.Request.Body)

		var reqdata UpdatePolicyRequest
		json.Unmarshal(reqBody, &reqdata)
		ctx, cancelfunc := sqlctx.WithTimeout(sqlctx.Background(), 5*time.Second)
		defer cancelfunc()
		stmt, err := s.conn.PrepareContext(ctx, InsertPolicyQuery)
		if err != nil {
			fmt.Printf("Error %s when preparing SQL statement", err)
			return
		}

		defer stmt.Close()
		res, err := stmt.ExecContext(ctx, ref, reqdata.Content)
		if err != nil {
			fmt.Printf("Error %s when inserting row into products table", err)
			return
		}
		rows, err := res.RowsAffected()
		if err != nil {
			fmt.Printf("Error %s when finding rows affected", err)
			return
		}

		log.Printf("%d rows inserted ", rows)

		context.String(http.StatusOK, string(rows)+" rows inserted ")
	}
}

func (s *Server) InsertPermInfo() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")
		reqBody, err := ioutil.ReadAll(context.Request.Body)
		// fmt.Printf(string(reqBody))
		var reqdata InsertPermInfoQueryRequest
		json.Unmarshal(reqBody, &reqdata)
		fmt.Printf("%+v\n", reqdata)
		ctx, cancelfunc := sqlctx.WithTimeout(sqlctx.Background(), 5*time.Second)
		defer cancelfunc()
		stmt, err := s.conn.PrepareContext(ctx, InsertPermInfoQuery)
		if err != nil {
			fmt.Printf("Error %s when preparing SQL statement", err)
			return
		}

		defer stmt.Close()
		res, err := stmt.ExecContext(ctx, reqdata.User_id, reqdata.Tbl_name, reqdata.Db_access_date, reqdata.Db_deny_date)
		if err != nil {
			fmt.Printf("Error %s when inserting row into products table", err)
			return
		}
		rows, err := res.RowsAffected()
		if err != nil {
			fmt.Printf("Error %s when finding rows affected", err)
			return
		}

		log.Printf("%d rows inserted ", rows)

		context.String(http.StatusOK, string(rows)+" rows inserted ")
		return
	}
}

func (s *Server) UpdateSecureDBAllow() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		reqBody, err := ioutil.ReadAll(context.Request.Body)
		fmt.Printf(string(reqBody))
		var reqdata UpdateSecureDBAllowRequest

		json.Unmarshal(reqBody, &reqdata)
		ctx, cancelfunc := sqlctx.WithTimeout(sqlctx.Background(), 5*time.Second)
		defer cancelfunc()
		stmt, err := s.conn.PrepareContext(ctx, UpdateSecureDBAllowQuery)
		if err != nil {
			fmt.Printf("Error %s when preparing SQL statement", err)
			return
		}

		defer stmt.Close()
		res, err := stmt.ExecContext(ctx, reqdata.Db_access_date, reqdata.User_id, reqdata.Tbl_name)
		if err != nil {
			fmt.Printf("Error %s when inserting row into products table", err)
			return
		}
		rows, err := res.RowsAffected()
		if err != nil {
			fmt.Printf("Error %s when finding rows affected", err)
			return
		}

		log.Printf("%d rows inserted ", rows)

		context.String(http.StatusOK, string(rows)+" rows updated ")
		return
	}
}

func (s *Server) UpdateSecureDBDeny() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		reqBody, err := ioutil.ReadAll(context.Request.Body)
		fmt.Printf(string(reqBody))
		var reqdata UpdateSecureDBDenyRequest

		json.Unmarshal(reqBody, &reqdata)
		ctx, cancelfunc := sqlctx.WithTimeout(sqlctx.Background(), 5*time.Second)
		defer cancelfunc()
		stmt, err := s.conn.PrepareContext(ctx, UpdateSecureDBDenyQuery)
		if err != nil {
			fmt.Printf("Error %s when preparing SQL statement", err)
			return
		}

		defer stmt.Close()
		res, err := stmt.ExecContext(ctx, reqdata.Db_deny_date, reqdata.User_id, reqdata.Tbl_name)
		if err != nil {
			fmt.Printf("Error %s when inserting row into products table", err)
			return
		}
		rows, err := res.RowsAffected()
		if err != nil {
			fmt.Printf("Error %s when finding rows affected", err)
			return
		}

		log.Printf("%d rows inserted ", rows)

		context.String(http.StatusOK, string(rows)+" rows updated ")
		return
	}
}

func (s *Server) SendJWT() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Header("Content-Type", "application/json")

		reqBody, err := ioutil.ReadAll(context.Request.Body)
		fmt.Printf(string(reqBody))

		if err != nil {
			fmt.Printf("server: could not read request body: %s\n", err)
		}

		var reqdata JWTRequest
		json.Unmarshal(reqBody, &reqdata)
		tokenString := reqdata.ClientMessage

		testkey := "123"
		parts := strings.Split(tokenString, ".")
		method := jwt.GetSigningMethod("HS256")
		err2 := method.Verify(strings.Join(parts[0:2], "."), parts[2], []byte(testkey))
		if err2 != nil {
			fmt.Printf("Error while verifying key: %v", err2)
		} else {
			fmt.Println("Correct key")
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(testkey), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			fmt.Printf("%+v \n", claims)
			// fmt.Println(claims["sub"])
			s.accessDateUpdate(claims["user"].(string), claims["sub"].(string))
			context.String(http.StatusOK, `{"server_message": "JWT received!"}`)
		} else {
			fmt.Println(err)
			context.String(http.StatusBadRequest, `{"server_message": "wrong JWT signature!"}`)
		}
	}

}

func (s *Server) accessDateUpdate(user_id string, dbauth string) {
	//parse dbauth
	list := strings.Split(dbauth, ",")
	mp := make(map[string]string)
	for _, line := range list {
		kv := strings.Split(line, ":")
		mp[kv[0]] = kv[1]
	}
	fmt.Println("%+v", mp)
	//query date
	for tbl, element := range mp {
		res, err := s.conn.Query(FindAccessDateQuery, user_id, tbl)
		fmt.Printf("query temp: %v, params: %v, %v\n", FindAccessDateQuery, user_id, tbl)

		if err != nil {
			fmt.Printf("Unable to execute sql_query, template: %v, params: %v, %v, err: %v\n",
				FindAccessDateQuery, user_id, tbl, err)
			return
		}

		defer func(res *sql.Rows) {
			err := res.Close()
			if err != nil {
				fmt.Printf("close res err: %v\n", err)
			}
		}(res)

		var result DBAccess

		if res.Next() {
			if err := res.Scan(&result.User_id, &result.Table_name, &result.Db_access_date, &result.Db_deny_date); err != nil {
				fmt.Printf("scan err: %v\n", err)
				return
			}
		} else {
			fmt.Printf("empty query result\n")
			return
		}

		fmt.Printf("actions: %+v\n", result)

		//update date
		days := 0
		if strings.Contains(element, "always") {
			days = 9999
		} else if strings.Contains(element, "once") {
			days = 0
		} else {
			re := regexp.MustCompile("[0-9]+")
			days, err = strconv.Atoi(re.FindAllString(element, -1)[0])
			if err != nil {
				days = 0
			}
		}
		// fmt.Println(days)
		if strings.Contains(element, "allow") {
			newallowdate, _ := time.Parse("2006-01-02", result.Db_access_date)
			newallowdate = time.Now().AddDate(0, 0, days)
			fmt.Println("new allow date : %v", newallowdate.Format("2006-01-02"))
			ctx, cancelfunc := sqlctx.WithTimeout(sqlctx.Background(), 5*time.Second)
			defer cancelfunc()
			stmt, err := s.conn.PrepareContext(ctx, UpdateSecureDBAllowQuery)
			if err != nil {
				fmt.Printf("Error %s when preparing SQL statement", err)
				return
			}
			defer stmt.Close()

			res, err := stmt.ExecContext(ctx, newallowdate.Format("2006-01-02"), &result.User_id, &result.Table_name)
			if err != nil {
				fmt.Printf("Error %s when inserting row into products table", err)
				return
			}
			rows, err := res.RowsAffected()
			if err != nil {
				fmt.Printf("Error %s when finding rows affected", err)
				return
			}

			log.Printf("%d rows inserted ", rows)
		} else {
			newdenydate, _ := time.Parse("2006-01-02", result.Db_deny_date)
			newdenydate = time.Now().AddDate(0, 0, days)
			fmt.Println("new deny date : %v", newdenydate.Format("2006-01-02"))
			ctx, cancelfunc := sqlctx.WithTimeout(sqlctx.Background(), 5*time.Second)
			defer cancelfunc()
			stmt, err := s.conn.PrepareContext(ctx, UpdateSecureDBDenyQuery)
			if err != nil {
				fmt.Printf("Error %s when preparing SQL statement", err)
				return
			}
			defer stmt.Close()

			res, err := stmt.ExecContext(ctx, newdenydate.Format("2006-01-02"), &result.User_id, &result.Table_name)
			if err != nil {
				fmt.Printf("Error %s when inserting row into products table", err)
				return
			}
			rows, err := res.RowsAffected()
			if err != nil {
				fmt.Printf("Error %s when finding rows affected", err)
				return
			}

			log.Printf("%d rows inserted ", rows)
		}

	}
}
