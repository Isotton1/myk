package main

import (
	//"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"flag"

	"github.com/Isotton1/myk/internal/common"
	"github.com/Isotton1/myk/internal/crypt"
	"github.com/Isotton1/myk/internal/database"
	//"github.com/Isotton1/myk/internal/models"
	"github.com/Isotton1/myk/internal/accounts"

	"golang.org/x/term"
)




// TODO
// - Maybe implement a opcional timestamp:
//   - flag: -ts
//   - encrypt the time with the ppid
//   - create the file with the encrypted time
//   - get the time and verify the diff with the ts time (15min timeout).
//
// - encrypt the salt/pepper ?
// - use flag stdlib (not a fan of using a lib for a thing that doesn't fully require a lib/abstraction, but it really makes my life easier).

func usage() {
	fmt.Print("Usages:\n",
			  "Access Key: myk <Account Name>\n",
			  "Create/Updade Account: myk -a <Account Name>\n")
}

func main() {
	argv := os.Args
	argc := len(argv)

	var flag_add bool
	flag.BoolVar(&flag_add, "a", false, "-a to add a new account")
	flag.BoolVar(&flag_add, "add", false, "--add to add a new account")
	flag.Usage = usage
	flag.Parse()

	home_dir, err := os.UserHomeDir()
	if err != nil {
		log.Panic(err)
	}

	db_path := home_dir + "/.local/share/myk/database.db"

	_, err = os.Stat(db_path); 
	if errors.Is(err, os.ErrNotExist) {
		db_file, err := os.Create(db_path)
		if err != nil {
			log.Panic(err)
		}
		db_file.Close()
	}

	db, err := database.Init_DB(db_path)
	if err != nil {
		log.Fatal(err)
	}

	username := os.Getenv("USER")
	exist, err := database.Has_user(db, username)
	if err != nil {
		log.Panic(err)
	}
	if !exist {
		fmt.Print("Enter a new master key: \n")
		master_key, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Panic(err)
		}
		
		err = accounts.New_user(db, username, master_key)
		if err != nil {
			if err == common.ErrUserExists {
				log.Fatal(err)
			}
			log.Panic(err)
		}
		os.Exit(0)
	}
	
	if argc < 2 {
		usage()
		os.Exit(0)
	}
	
	fmt.Print("Enter the master key: \n")
	master_key, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Panic(err)
	}

	user, err := database.Get_user(db, username)
	if err != nil {
		log.Panic(err)
	}
	
	if !accounts.Verify_master(user, master_key) {
		log.Fatal("Wrong key")
	}

	if flag_add {
		fmt.Print("Enter a new key for the Account: \n")
		new_key, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Panic(err)
		}

		account := argv[2]
		err = accounts.New_acc(db, user, account, master_key, new_key)
		if err != nil {
			if err == common.ErrNoUserFound {
				log.Fatal(err)
			}
			log.Panic(err)
		}
		os.Exit(0)
	}
	
	account := argv[1]
	
	account_key_struct, err := database.Get_key(db, user.ID, account)
	if err != nil {
		if err == common.ErrNoAccFound {
			log.Fatal(err)
		}
		log.Panic(err)
	}
	account_key, err := crypt.Decrypt(account_key_struct.Key, master_key)
	if err != nil {
		log.Panic("Error during Decrypt(): " + err.Error())
	}

	fmt.Println(string(account_key))
}
