package main

import (
	"log"
	"os"

	grpcserver "github.com/kartik7120/booking_auth_service/cmd/api/grpcServer"
	"github.com/kartik7120/booking_auth_service/cmd/helper"
)

func main() {
	conn, err := helper.ConnectToDB()
	defer conn.Close()

	if err != nil {
		log.Println("Could not connect to postgres database")
		os.Exit(1)
	}

	api := grpcserver.Config{
		DbConfig: helper.DBConfig{
			Conn: conn,
		},
	}

}
