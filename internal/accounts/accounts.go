package accounts

import (
	"bytes"
	"database/sql"
	
	//"github.com/Isotton1/myk/internal/common"
	"github.com/Isotton1/myk/internal/crypt"
	"github.com/Isotton1/myk/internal/database"
	"github.com/Isotton1/myk/internal/models"	
)

func New_user(db *sql.DB, username string, master []byte) error {
	salt, err := crypt.Random_bytes(128)
	if err != nil {
		return err
	}

	pepper, err := crypt.Random_bytes(128)
	if err != nil {
		return err
	}
	
	var plaintext_buf bytes.Buffer
	plaintext_buf.Write(salt)
	plaintext_buf.Write(master)
	plaintext_buf.Write(pepper)
	plaintext := plaintext_buf.Bytes()

	master_hash := crypt.New_hash(plaintext)
	user := models.User{
		Username:     username,
		Master_key: master_hash,
		Salt:         salt,
		Pepper:       pepper,
	}
	
	err = database.Insert_user(db, &user)
	if err != nil {
		return err
	}

	return nil
}

func New_acc(db *sql.DB, user models.User, account string, master, key []byte) error {
	encrypted_key, err := crypt.Encrypt(key, master)
	if err != nil {
		return err
	}

	key_struct := models.Key{
		User_ID:   user.ID,
		Account:  account,
		Key: encrypted_key,
	}

	err = database.Insert_key(db, &key_struct)
	if err != nil {
		return err
	}
	
	return nil
}

func Verify_master(user models.User, master_key []byte) bool {
	master_hash := user.Master_key
	salt := user.Salt
	pepper := user.Pepper
	
	var plaintext_buf bytes.Buffer
	plaintext_buf.Write(salt)
	plaintext_buf.Write(master_key)
	plaintext_buf.Write(pepper)
	plaintext := plaintext_buf.Bytes()

	key_hash := crypt.New_hash(plaintext)

	return bytes.Equal(key_hash, master_hash)
}
