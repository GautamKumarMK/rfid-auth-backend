package main

import (
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrations embed.FS

var (
	ErrDirty = errors.New("database is dirty")
	ErrLocked = errors.New("another migration holds the lock")
	ErrInterrupter = errors.New("migration is interrupted")
)

type MigratorOptions struct {
	LockTimeout time.Duration
	Logger *slog.Logger
}

type Migrator struct {
	m *migrate.Migrate
}

func NewMigrator(dbUrl string, opt MigratorOptions) (*Migrator, error) {
	u, err := url.Parse(dbUrl)
	if err != nil {
		return nil, errors.New("parse database url: malformed URL")
	}

	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, fmt.Errorf("unsupported database url scheme %q (want postgres or postgresql)", u.Scheme)
	}
	u.Scheme = "pgx5"

	src, err := iofs.New(migrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("load embedded migrations: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, u.String())
	if err != nil {
		src.Close()
		return nil, fmt.Errorf("connect to %s: %w", u.Redacted(), err)
	}
	if opt.LockTimeout > 0 {
		m.LockTimeout = opt.LockTimeout
	}
	if opt.Logger != nil {
		m.Log = slogAdapter{opt.Logger}
	}
	return &Migrator{m: m}, nil
}

type slogAdapter struct{l *slog.Logger}

func (a slogAdapter) Printf(format string, v ...any) {
	a.l.Info("migrate", "msg", fmt.Sprintf(format, v...))
}

func (a slogAdapter) Verbose() bool { return false }