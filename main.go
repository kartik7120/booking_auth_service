package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/joho/godotenv"
	a "github.com/kartik7120/booking_auth_service/cmd/auth"
	auth "github.com/kartik7120/booking_auth_service/cmd/grpcServer"
	"github.com/kartik7120/booking_auth_service/cmd/grpcServer/server"
	"github.com/kartik7120/booking_auth_service/cmd/helper"
)

func main() {
	err := godotenv.Load()
	log.SetOutput(os.Stdout)
	log.SetReportCaller(true)

	if os.Getenv("ENV") == "production" {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.DebugLevel)
	}

	if err != nil {
		log.Error("Error loading .env file")
		panic(err)
	}

	lis, err := net.Listen("tcp", ":1101")

	if err != nil {
		log.Error("Error starting the server")
		panic(err)
	}

	// Creating a new grpc server

	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	// Connect to database

	DB, err := helper.ConnectToDB()

	if err != nil {
		log.Error("Error connecting to database")
		panic(err)
	}

	authObj := a.NewAuthentication(10)
	authObj.DB = &helper.DBConfig{
		Conn: DB,
	}

	auth.RegisterAuthServiceServer(grpcServer, &server.AuthService{
		Authentication: authObj,
	})

	reflection.Register(grpcServer)

	go func() {
		log.Info("Starting the auth service")
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println("Error starting the server")
			panic(err)
		}
	}()

	<-signalChan

	log.Info("Stopping the server")
	grpcServer.GracefulStop()
}
