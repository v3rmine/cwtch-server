module git.openprivacy.ca/cwtch.im/server

go 1.14

require (
	cwtch.im/cwtch v0.8.5
	git.openprivacy.ca/cwtch.im/tapir v0.4.9
	git.openprivacy.ca/openprivacy/connectivity v1.5.0
	git.openprivacy.ca/openprivacy/log v1.0.3
	github.com/gtank/ristretto255 v0.1.2
	github.com/mattn/go-sqlite3 v1.14.7
	github.com/struCoder/pidusage v0.2.1
	golang.org/x/crypto v0.0.0-20201012173705-84dcc777aaee
)

replace cwtch.im/cwtch => /home/dan/src/go/src/cwtch.im/cwtch
