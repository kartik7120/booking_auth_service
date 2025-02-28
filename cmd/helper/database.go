package helper

import (
	"database/sql"
	"log"
	"os"
	"time"
)

type DBConfig struct {
	Conn *sql.DB
}

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func ConnectToDB() (*sql.DB, error) {
	var count int64
	dsn := os.Getenv("DSN")

	for {
		conn, err := openDB(dsn)
		if err != nil {
			log.Println("Postgres is not ready yet...")
			count++
		} else {
			log.Println("Connected to Postgres Successfully")
			return conn, nil
		}

		if count > 10 {
			log.Println("Could not connect to Postgres")
			return nil, err
		}

		log.Println("Backingoff for 2 seconds...")
		time.Sleep(time.Second * 2)
		continue
	}
}

func (d *DBConfig) SelectDB(queryString string) (sql.Result, error) {
	result, err := d.Conn.Exec(queryString)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (d *DBConfig) InsertDB(queryString string) (sql.Result, error) {
	result, err := d.Conn.Exec(queryString)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (d *DBConfig) UpdateDB(queryString string) (sql.Result, error) {
	result, err := d.Conn.Exec(queryString)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (d *DBConfig) DeleteDB(queryString string) (sql.Result, error) {
	result, err := d.Conn.Exec(queryString)
	if err != nil {
		return nil, err
	}

	return result, nil
}
