package database

import (
	"database/sql"

	"github.com/Isotton1/myk/internal/common"
	"github.com/Isotton1/myk/internal/models"

	_ "modernc.org/sqlite"
)

func Init_DB(url string)  (*sql.DB, error) {
	db, err := sql.Open("sqlite", url)
	if err != nil {
		return nil, err
	}

	users_table := `
	CREATE TABLE IF NOT EXISTS Users (
		user_id INTEGER PRIMARY KEY AUTOINCREMENT,
		username BINARY NOT NULL UNIQUE,
		master_key BINARY NOT NULL,
		salt BINARY NOT NULL,
		pepper BINARY NOT NULL
	);`
	key_table := `
	CREATE TABLE IF NOT EXISTS Keys (
		key_id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		account BINARY NOT NULL UNIQUE,
		key BINARY NOT NULL,
		FOREIGN KEY (user_id) REFERENCES Users(user_id)
	);`

	_, err = db.Exec(users_table)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(key_table)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func Insert_user(db *sql.DB, user *models.User) error {
	exist, err := Has_user(db, user.Username)
	if err != nil {
		return err
	}
	if exist {
		return common.ErrUserExists
	}
	query := `INSERT INTO Users(username, master_key, salt, pepper) VALUES(?, ?, ?, ?)`
	_, err = db.Exec(query, user.Username, user.Master_key, user.Salt, user.Pepper)
	if err != nil {
		return err
	}
	return nil
}

func Insert_key(db *sql.DB, key *models.Key) error {
	exist, err := Has_user(db, key.Account)
	if err != nil {
		return err
	}
	if exist {
		query := `UPDATE Keys SET account = ?, key = ? WHERE user_id = ?`
		_, err = db.Exec(query, key.Account, key.Key, key.User_ID)
		if err != nil {
			return err
		}
		return nil
	}
	query := `INSERT INTO Keys(user_id, account, key) VALUES(?, ?, ?)`
	_, err = db.Exec(query, key.User_ID, key.Account, key.Key)
	if err != nil {
		return err
	}
	return nil
}

func Get_user(db *sql.DB, username string) (models.User, error) {
	var user_ID int
	var master_hash, salt, pepper []byte
	err := db.QueryRow("SELECT user_id, master_key, salt, pepper FROM users WHERE username = ?", username).Scan(&user_ID, &master_hash, &salt, &pepper)
	if err != nil {
		if err == sql.ErrNoRows {
			return models.User{}, common.ErrNoUserFound
		}
		return models.User{}, err
	}

	user := models.User{
		ID:           user_ID,
		Username:     username,
		Master_key: master_hash,
		Salt:         salt,
		Pepper:       pepper,
	}
	return user, nil
}

func Get_key(db *sql.DB, user_ID int, account string) (models.Key, error) {
	var key []byte
	err := db.QueryRow("SELECT key FROM Keys WHERE account = ? AND user_id = ?", account, user_ID).Scan(&key)
	if err != nil {
		if err == sql.ErrNoRows {
			return models.Key{}, common.ErrNoAccFound
		}
		return models.Key{}, err
	}

	key_struct := models.Key{
		User_ID:   user_ID,
		Account:  account,
		Key: 	  key,
	}
	return key_struct, nil
}

func Has_user(db *sql.DB, username string) (bool, error) {
	var exist bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM Users WHERE username = ?)", username).Scan(&exist)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}

	return exist, nil
}

func Has_key(db *sql.DB, user_ID string) (bool, error) {
	var exist bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM Keys WHERE user_id = ?)", user_ID).Scan(&exist)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}

	return exist, nil
}
