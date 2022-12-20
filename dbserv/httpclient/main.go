package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

const serverPort = 3333

func main() {
	// go func() {
	// 	mux := http.NewServeMux()
	// 	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 		fmt.Printf("server: %s /\n", r.Method)
	// 		fmt.Fprintf(w, `{"message": "hello!"}`)
	// 	})
	// 	server := http.Server{
	// 		Addr:    fmt.Sprintf(":%d", serverPort),
	// 		Handler: mux,
	// 	}
	// 	if err := server.ListenAndServe(); err != nil {
	// 		if !errors.Is(err, http.ErrServerClosed) {
	// 			fmt.Printf("errpr running http server: %s\n", err)
	// 		}
	// 	}
	// }()
	// time.Sleep(100 * time.Millisecond)
	jsonBody := []byte(`{"user_id": "dbtest", "tbl_name":"user_attrs", "db_access_date": "2022-12-20"}`)
	bodyReader := bytes.NewReader(jsonBody)

	requestURL := fmt.Sprintf("http://localhost:%d/test", serverPort)
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
}
