package models

type User struct {
	ID           int    `db:"user_id"`
	Username     string `db:"username"`
	Master_key   []byte `db:"master_hash"`
	Salt         []byte `db:"salt"`
	Pepper       []byte `db:"pepper"`
}

type Key struct {
	User_ID   int    `db:"user_id"`
	Account   string `db:"account"`
	Key       []byte `db:"key"`
}
