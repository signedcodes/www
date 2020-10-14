package main

import (
	"context"

	"crawshaw.io/sqlite/sqlitex"
)

const (
	createSignerTable = `
create table if not exists signer (
	id integer not null primary key,
	created datetime default (datetime('now')),
	login text not null,
	name text not null,
	avatar text not null,
	code text not null default "",
	slug text not null default "",
	donations integer not null default 0,
	constraint login_uniq unique (login)
);`

	createRefcodeTable = `
create table if not exists refcode (
	id integer not null primary key,
	created datetime default (datetime('now')),
	opaque text not null,
	login text not null,
	amount integer not null,
	constraint opaque_uniq unique (opaque)
);`
)

func (s *Server) createTables() error {
	conn := s.DBPool.Get(context.Background())
	defer s.DBPool.Put(conn)
	for _, sql := range []string{createSignerTable, createRefcodeTable} {
		if err := sqlitex.Exec(conn, sql, nil); err != nil {
			return err
		}
	}
	return nil
}
