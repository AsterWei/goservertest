package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	jwt "github.com/golang-jwt/jwt/v4"
)

const serverPort = 3333

const keyServerAddr = "serverAddr"

type JWTRequest struct {
	ClientMessage string `json:"client_message"`
}

type UserAttrs struct {
	Attrs string
}

type Server struct {
	conn *sql.DB
}

func getRoot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hasFirst := r.URL.Query().Has("first")
	first := r.URL.Query().Get("first")
	hasSecond := r.URL.Query().Has("second")
	second := r.URL.Query().Get("second")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("could not read body: %s\n", err)
	}

	fmt.Printf("%s: got / request. first(%t)=%s, second(%t)=%s, body:\n%s\n",
		ctx.Value(keyServerAddr),
		hasFirst, first,
		hasSecond, second,
		body)
	io.WriteString(w, "This is my website!\n")
}
func getHello(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	fmt.Printf("%s: got /hello request\n", ctx.Value(keyServerAddr))
	myString := r.PostFormValue("myString")
	if myString == "" {
		w.Header().Set("x-missing-field", "MyString")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	io.WriteString(w, fmt.Sprintf("Hello, %s!\n", myString))
}

func getTest(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("server: %s /test\n", r.Method)
	fmt.Printf("server: query id: %s\n", r.URL.Query().Get("id"))
	fmt.Printf("server: content-type: %s\n", r.Header.Get("content-type"))
	fmt.Printf("server: headers:\n")
	for headerName, headerValue := range r.Header {
		fmt.Printf("\t%s = %s\n", headerName, strings.Join(headerValue, ", "))
	}

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("server: could not read request body: %s\n", err)
	}
	fmt.Printf("server: request body: %s\n", reqBody)

	fmt.Fprintf(w, `{"message": "hello!"}`)
}

func getJWT(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("server: %s receiving JWT\n", r.Method)
	fmt.Printf("server: content-type: %s \n", r.URL.Query().Get("id"))
	for headerName, headerValue := range r.Header {
		fmt.Printf("\t%s = %s\n", headerName, strings.Join(headerValue, ", "))
	}
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("server: could not read request body: %s\n", err)
	}
	fmt.Fprintf(w, `{"message": "JWT todoita!"}`)
	var reqdata JWTRequest
	json.Unmarshal(reqBody, &reqdata)
	fmt.Printf("server: client message %s \n", reqdata.ClientMessage)
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
		fmt.Println(claims["sub"])
	} else {
		fmt.Println(err)
	}

}

// func run will be responsible for setting up db connections, routers etc
func run() error {
	//// I'm used to working with postgres, but feel free to use any db you like. You just have to change the driver
	//// I'm not going to cover how to create a database here but create a database
	//// and call it something along the lines of "weight tracker"
	connectionString := "root:123456@tcp(localhost:3306)/abac"

	// setup database connection
	db, err := setupSQLDatabase("mysql", connectionString)

	if err != nil {
		return err
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	// router := gin.Default()
	// router.Use(cors.Default())

	// server := app.NewServer(router, db)

	// err = server.Run()

	// if err != nil {
	// 	return err
	// }
	id := "Aster"
	sqlTemp := "SELECT attrs FROM user_attrs WHERE user_id=?"
	var tmpattrs UserAttrs
	err = db.QueryRow(sqlTemp, id).Scan(&tmpattrs.Attrs)
	if err != nil {
		return err
	}
	fmt.Println(tmpattrs.Attrs)
	return nil
}

func setupSQLDatabase(driverName string, connString string) (*sql.DB, error) {
	// change "postgres" for whatever supported database you want to use
	db, err := sql.Open(driverName, connString)

	if err != nil {
		return nil, err
	}

	// ping the DB to ensure that it is connected
	err = db.Ping()

	if err != nil {
		return nil, err
	}

	return db, nil
}

func main() {
	if err := run(); err != nil {
		_, err := fmt.Fprintf(os.Stderr, "this is the startup error: %s\\n", err)
		if err != nil {
			return
		}
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", getRoot)
	mux.HandleFunc("/hello", getHello)
	mux.HandleFunc("/test", getTest)
	mux.HandleFunc("/jwt", getJWT)
	ctx, cancelCtx := context.WithCancel(context.Background())
	serverOne := &http.Server{
		Addr:    ":3333",
		Handler: mux,
		BaseContext: func(l net.Listener) context.Context {
			ctx = context.WithValue(ctx, keyServerAddr, l.Addr().String())
			return ctx
		},
	}
	go func() {
		err := serverOne.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("server one closed\n")
		} else if err != nil {
			fmt.Printf("error listening for server one: %s\n", err)
		}
		cancelCtx()
	}()

	time.Sleep(10 * time.Millisecond)
	jsonBody := []byte(`{"client_message": "hello, server!"}`)
	bodyReader := bytes.NewReader(jsonBody)

	requestURL := fmt.Sprintf("http://localhost:%d/test?id=1234", serverPort)
	req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("client: error making http request: %s\n", err)
		os.Exit(1)
	}

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("client: could not read response body: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("client: response body: %s\n", resBody)

	fmt.Printf("client: got response!\n")
	fmt.Printf("client: status code: %d\n", res.StatusCode)

	<-ctx.Done()
}
