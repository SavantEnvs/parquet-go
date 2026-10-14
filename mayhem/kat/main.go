// mayhem/kat — known-answer-test probe for mayhem/test.sh.
//
// WHY A SEPARATE BINARY (SPEC §6.3 anti-reward-hacking):
// `go test` links a STATIC binary, so the verify-repo sabotage check (which
// LD_PRELOADs a shim whose constructor calls _exit(0) for non-system
// executables) cannot neuter it — a suite that only runs `go test` is
// therefore immune to the sabotage check and does NOT prove the oracle is
// behavioral. This probe is built with cgo (see cgo_dynamic.go) so it is
// DYNAMICALLY linked: the shim reaches it, the process becomes an instant
// no-op, it prints nothing, and test.sh's exact string assertions below fail.
// That is what makes the oracle sabotage-detecting.
//
// It is also a real KAT, not a liveness check: it writes a small Parquet
// file with known typed rows USING THE LIBRARY ITSELF, reads it back through
// parquet.OpenFile + parquet.NewReader, and asserts the EXACT round-tripped
// values plus three metadata facts (row count, column count, first schema
// field name). A patch that stubs the writer or reader to stop a crash
// cannot reproduce these exact values, so it fails the oracle.
//
// Prints lines of the form KAT_<NAME>=<value>, which test.sh matches EXACTLY.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/parquet-go/parquet-go"
)

type katRow struct {
	Name   string  `parquet:"name"`
	Age    int32   `parquet:"age"`
	Score  float64 `parquet:"score"`
	Active bool    `parquet:"active"`
}

func main() {
	rows := []katRow{
		{Name: "alice", Age: 30, Score: 12.25, Active: true},
		{Name: "bob", Age: 41, Score: 3.5, Active: false},
		{Name: "carol", Age: 22, Score: 100.125, Active: true},
	}

	// ── 1) write a real Parquet file with the library itself ────────────
	var buf bytes.Buffer
	w := parquet.NewWriter(&buf)
	for _, row := range rows {
		if err := w.Write(row); err != nil {
			fmt.Fprintf(os.Stderr, "kat: write: %v\n", err)
			os.Exit(1)
		}
	}
	if err := w.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "kat: writer close: %v\n", err)
		os.Exit(1)
	}
	data := buf.Bytes()

	// ── 2) read the footer/schema back and report metadata facts ────────
	pf, err := parquet.OpenFile(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "kat: OpenFile: %v\n", err)
		os.Exit(1)
	}
	fields := pf.Schema().Fields()
	if len(fields) == 0 {
		fmt.Fprintln(os.Stderr, "kat: schema has no fields")
		os.Exit(1)
	}
	fmt.Printf("KAT_ROWCOUNT=%d\n", pf.NumRows())
	fmt.Printf("KAT_COLCOUNT=%d\n", len(pf.Schema().Columns()))
	fmt.Printf("KAT_FIELD_NAME=%s\n", fields[0].Name())

	// ── 3) read every row back and report exact round-tripped values ────
	r := parquet.NewReader(pf)
	got := make([]katRow, 0, len(rows))
	for {
		var row katRow
		if err := r.Read(&row); err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "kat: read: %v\n", err)
			os.Exit(1)
		}
		got = append(got, row)
	}
	if len(got) != len(rows) {
		fmt.Fprintf(os.Stderr, "kat: got %d rows, want %d\n", len(got), len(rows))
		os.Exit(1)
	}
	fmt.Printf("KAT_ROW0_NAME=%s\n", got[0].Name)
	fmt.Printf("KAT_ROW1_AGE=%d\n", got[1].Age)
	fmt.Printf("KAT_ROW2_SCORE=%.3f\n", got[2].Score)
	fmt.Printf("KAT_ROW1_ACTIVE=%t\n", got[1].Active)
}
