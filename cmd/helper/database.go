package helper

import (
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DBConfig struct {
	Conn *gorm.DB
}

func ConnectToDB() (*gorm.DB, error) {
	var count int64
	dsn := os.Getenv("DSN")

	for {
		// conn, err := openDB(dsn)
		db, err := gorm.Open(postgres.New(postgres.Config{
			DSN:                  dsn,
			PreferSimpleProtocol: true,
		}), &gorm.Config{})

		if err != nil {
			log.Println("Postgres is not ready yet...")
			count++
		} else {
			log.Println("Connected to Postgres Successfully")
			return db, nil
		}

		if count > 10 {
			log.Println("Could not connect to Postgres")
			return nil, err
		}

		log.Println("Backing off for 2 seconds...")
		time.Sleep(time.Second * 2)
		continue
	}
}
