package main

import (
	"context"

	"crawshaw.io/sqlite/sqlitex"
)

const (
	createSignerTable = `
create table if not exists signer (
	login text not null primary key,
	created datetime default (datetime('now')),
	name text not null,
	email text not null,
	avatar text not null,
	link text not null
);`

	// Snippets are bits of code that a signer will sign.
	// Each snippet has some `code` that is written by a `signer`,
	// has a `slug` to indicate the benefactor,
	// has a `number` of prints available,
	// and has a donation `amount` per print.
	createSnippetTable = `
create table if not exists snippet (
	id text not null primary key,
	created datetime default (datetime('now')),
	signer text not null,
	code text not null,
	comment text not null,
	slug text not null,
	quantity integer not null,
	amount integer not null
);`

	createRefcodeTable = `
create table if not exists refcode (
	id text not null primary key,
	created datetime default (datetime('now')),
	login text not null,
	snippet text not null,
	recipient text
);`
)

func (s *Server) createTables() error {
	conn := s.DBPool.Get(context.Background())
	defer s.DBPool.Put(conn)
	for _, sql := range []string{createSignerTable, createSnippetTable, createRefcodeTable} {
		if err := sqlitex.Exec(conn, sql, nil); err != nil {
			return err
		}
	}
	return nil
}
