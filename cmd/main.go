package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/joho/godotenv"
	auth "github.com/kartik7120/booking_auth_service/cmd/grpcServer"
	"github.com/kartik7120/booking_auth_service/cmd/grpcServer/server"
)

func main() {
	err := godotenv.Load()

	if err != nil {
		fmt.Println("Error loading .env file")
		panic(err)
	}

	lis, err := net.Listen("tcp", ":1101")

	if err != nil {
		fmt.Println("Error starting the server")
		panic(err)
	}

	// Creating a new grpc server

	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	auth.RegisterAuthServiceServer(grpcServer, &server.AuthService{})

	reflection.Register(grpcServer)

	go func() {
		fmt.Println("Auth Service started")
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println("Error starting the server")
			panic(err)
		}
	}()

	<-signalChan

	fmt.Println("Shutting down the auth service")
	grpcServer.GracefulStop()
}
