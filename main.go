package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/Isotton1/myk/internal/common"
	"github.com/Isotton1/myk/internal/crypt"
	"github.com/Isotton1/myk/internal/database"
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
// - fix add
// - install.sh
// - list
func usage() {
	fmt.Print(
		"Usages:\n",
		"Access Key:      myk <Account Name>\n",
		"Add/Updade Key:  myk -a <Account Name>\n",
		"Remove Key:      myk -rm <Account Name>\n",
	)
}

func main() {
	argv := os.Args
	argc := len(argv)

	var flag_add bool
	var flag_remove bool
	flag.BoolVar(&flag_add, "a", false, "-a to add a new account")
	flag.BoolVar(&flag_add, "add", false, "--add to add a new account")
	flag.BoolVar(&flag_remove, "rm", false, "-rm to remove a account")
	flag.BoolVar(&flag_remove, "remove", false, "--remove to remove a account")
	flag.Usage = usage
	flag.Parse()

	home_dir, err := os.UserHomeDir()
	if err != nil {
		log.Panic(err)
	}

	db_path := home_dir + "/.local/share/myk/database.db"

	_, err = os.Stat(db_path)
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

	//Login
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
	//

	//Add
	if flag_add || strings.EqualFold(argv[1], "add") {
		if argc < 3 {
			usage()
			os.Exit(1)
		}
		fmt.Print("Enter a new key for the Account: \n")
		new_key, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Panic(err)
		}

		account := argv[2]
		err = accounts.New_acc(db, user, account, master_key, new_key)
		if err != nil {
			log.Panic(err)
		}
		os.Exit(0)
	}
	//

	//Remove
	if flag_remove || strings.EqualFold(argv[1], "remove") {
		if argc < 3 {
			usage()
			os.Exit(1)
		}
		account := argv[2]

	confirm:
		fmt.Printf("Remove %s key? (y/n): \n", account)
		var input byte
		_, err := fmt.Scanf("%c\n", &input)
		if err != nil {
			log.Panic(err)
		}

		switch input {
		case 'y':
			err = accounts.Remove_acc(db, user.ID, account)
			if err != nil {
				if err == common.ErrNoAccFound {
					log.Fatal(err)
				}
				log.Panic(err)
			}
			fmt.Printf("%s key removed successively\n", account)
		case 'n':
			break
		case 'q':
			break
		default:
			goto confirm
		}
		
		os.Exit(0)
	}
	//

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
