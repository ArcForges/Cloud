// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var legacyIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

type ctr06ArchiveTable struct {
	Name    string
	Columns []string
	Rows    int64
	SHA256  string
}

// This observes what the archive actually contains. It never reconstructs
// unrecorded source row counts or claims the original snapshot was observed.
func ctr06LegacyArchiveTables(ctx context.Context, tool string, env []string, archive *os.File) ([]ctr06ArchiveTable, error) {
	names, err := ctr06RequiredTablesFrom(ctr06Schema10Inventory)
	if err != nil {
		return nil, err
	}
	observed := make([]ctr06ArchiveTable, 0, len(names))
	for _, name := range names {
		parts := strings.Split(name, ".")
		if len(parts) != 2 || !legacyIdentifier.MatchString(parts[0]) || !legacyIdentifier.MatchString(parts[1]) {
			return nil, errors.New("the supported legacy table inventory is malformed")
		}
		if _, err := archive.Seek(0, io.SeekStart); err != nil {
			return nil, errors.New("the legacy archive cannot be rewound")
		}
		command := exec.CommandContext(ctx, tool, "--file=-", "--data-only", "--schema="+parts[0], "--table="+parts[1])
		command.Env, command.Stdin, command.Stderr = env, archive, io.Discard
		command.WaitDelay = 5 * time.Second
		pipe, err := command.StdoutPipe()
		if err != nil || command.Start() != nil {
			return nil, errors.New("the legacy archive data could not be observed")
		}
		entry, readErr := ctr06ReadArchivedCopy(pipe, name)
		if readErr != nil {
			_ = command.Process.Kill()
		}
		waitErr := command.Wait()
		if readErr != nil || waitErr != nil {
			return nil, errors.New("a legacy archive table data stream is corrupt or incomplete")
		}
		observed = append(observed, entry)
	}
	return observed, nil
}

func ctr06ReadArchivedCopy(input io.Reader, name string) (ctr06ArchiveTable, error) {
	entry := ctr06ArchiveTable{Name: name}
	reader := bufio.NewReaderSize(input, 64*1024)
	digest := sha256.New()
	inside, ended, firstChunk := false, false, true
	for {
		line, prefix, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return entry, err
		}
		if !inside {
			if prefix {
				return entry, errors.New("legacy archive SQL header is too long")
			}
			if bytes.HasPrefix(line, []byte("COPY ")) {
				if ended {
					return entry, errors.New("legacy archive has duplicate table data")
				}
				columns, err := ctr06LegacyCopyHeader(string(line), name)
				if err != nil {
					return entry, err
				}
				entry.Columns, inside, firstChunk = columns, true, true
			}
			continue
		}
		if firstChunk && !prefix && bytes.Equal(line, []byte(`\.`)) {
			inside, ended = false, true
			continue
		}
		_, _ = digest.Write(line)
		if !prefix {
			_, _ = digest.Write([]byte{'\n'})
			entry.Rows++
		}
		firstChunk = !prefix
	}
	if inside || !ended || len(entry.Columns) == 0 {
		return entry, errors.New("legacy archive table data is missing")
	}
	entry.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return entry, nil
}

func ctr06LegacyCopyHeader(line, name string) ([]string, error) {
	const prefix, suffix = "COPY ", ") FROM stdin;"
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, suffix) {
		return nil, errors.New("the legacy COPY header is unsupported")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix)
	before, columns, ok := strings.Cut(body, " (")
	parts, expected := strings.Split(before, "."), strings.Split(name, ".")
	if !ok || len(parts) != 2 || len(expected) != 2 {
		return nil, errors.New("the legacy COPY table differs from the closed inventory")
	}
	for i, part := range parts {
		if strings.HasPrefix(part, `"`) && strings.HasSuffix(part, `"`) && len(part) > 1 {
			part = part[1 : len(part)-1]
		}
		if !legacyIdentifier.MatchString(part) || part != expected[i] {
			return nil, errors.New("the legacy COPY table differs from the closed inventory")
		}
	}
	seen := make(map[string]bool)
	var result []string
	for _, item := range strings.Split(columns, ",") {
		column := strings.TrimSpace(item)
		if strings.HasPrefix(column, `"`) && strings.HasSuffix(column, `"`) && len(column) > 1 {
			column = column[1 : len(column)-1]
		}
		if !legacyIdentifier.MatchString(column) || seen[column] {
			return nil, errors.New("the legacy COPY columns are invalid or ambiguous")
		}
		seen[column] = true
		result = append(result, column)
	}
	return result, nil
}

type ctr06CountingHash struct {
	digest io.Writer
	rows   int64
}

func (w *ctr06CountingHash) Write(data []byte) (int, error) {
	w.rows += int64(bytes.Count(data, []byte{'\n'}))
	return w.digest.Write(data)
}

func ctr06VerifyLegacyTables(ctx context.Context, conn *pgx.Conn, expected []ctr06ArchiveTable) error {
	for _, table := range expected {
		parts := strings.Split(table.Name, ".")
		if len(parts) != 2 {
			return errors.New("the legacy target table inventory is invalid")
		}
		rows, err := conn.Query(ctx, `SELECT a.attname FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2 AND a.attnum>0 AND NOT a.attisdropped AND a.attgenerated=''
 ORDER BY a.attnum`, parts[0], parts[1])
		if err != nil {
			return errors.New("the legacy target columns are unreadable")
		}
		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return errors.New("the legacy target columns are incomplete")
			}
			names = append(names, name)
		}
		rows.Close()
		if rows.Err() != nil || len(names) != len(table.Columns) {
			return errors.New("the legacy target column inventory differs")
		}
		quoted := make([]string, len(names))
		for i, name := range names {
			if name != table.Columns[i] {
				return errors.New("the legacy target column order differs")
			}
			quoted[i] = pgx.Identifier{name}.Sanitize()
		}
		digest := sha256.New()
		writer := &ctr06CountingHash{digest: digest}
		statement := "COPY " + pgx.Identifier{parts[0], parts[1]}.Sanitize() + " (" + strings.Join(quoted, ",") + ") TO STDOUT"
		tag, err := conn.PgConn().CopyTo(ctx, writer, statement)
		if err != nil || tag.RowsAffected() != table.Rows || writer.rows != table.Rows || hex.EncodeToString(digest.Sum(nil)) != table.SHA256 {
			return errors.New("the restored legacy table differs from the observed archive data")
		}
	}
	return nil
}

// ctr06LegacyBlobEntries obtains actual OIDs from the TOC, then the ordinary
// inventory checker requires exactly one metadata and one data entry per OID.
func ctr06LegacyBlobEntries(raw []byte) ([]ctr06BackupLargeObject, []byte, error) {
	seen := map[uint32]bool{}
	var listing bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), restoreTOCMax)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 8 && parts[3] == "BLOB" && parts[4] == "METADATA" && parts[5] == "-" {
			n, err := strconv.ParseUint(parts[6], 10, 32)
			if err != nil || n == 0 || seen[uint32(n)] {
				return nil, nil, errors.New("legacy large-object metadata is ambiguous")
			}
			seen[uint32(n)] = true
			fmt.Fprintln(&listing, line)
		} else if len(parts) == 7 && parts[3] == "BLOBS" && parts[4] == "-" {
			fmt.Fprintln(&listing, line)
		}
	}
	if scanner.Err() != nil {
		return nil, nil, errors.New("legacy large-object inventory is unreadable")
	}
	objects := make([]ctr06BackupLargeObject, 0, len(seen))
	for oid := range seen {
		objects = append(objects, ctr06BackupLargeObject{OID: oid})
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].OID < objects[j].OID })
	return objects, listing.Bytes(), nil
}

// A selected large-object data stream is parsed as the exact SQL emitted by
// pg_restore, decoding its chunks only into a digest, never into logs/files.
func ctr06LegacyArchiveLargeObjects(ctx context.Context, tool string, env []string, archive *os.File, listPath string, expected []ctr06BackupLargeObject) ([]ctr06BackupLargeObject, error) {
	if len(expected) == 0 {
		return []ctr06BackupLargeObject{}, nil
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New("the legacy archive cannot be rewound")
	}
	command := exec.CommandContext(ctx, tool, "--file=-", "--data-only", "--use-list="+listPath)
	command.Env, command.Stdin, command.Stderr = env, archive, io.Discard
	command.WaitDelay = 5 * time.Second
	pipe, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		return nil, errors.New("the legacy large-object stream could not be observed")
	}
	result, readErr := ctr06ReadArchivedLargeObjects(pipe, expected)
	if readErr != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if readErr != nil || waitErr != nil {
		return nil, errors.New("the legacy large-object stream is corrupt or incomplete")
	}
	return result, nil
}

func ctr06ReadArchivedLargeObjects(input io.Reader, expected []ctr06BackupLargeObject) ([]ctr06BackupLargeObject, error) {
	openPattern := regexp.MustCompile(`^SELECT pg_catalog[.]lo_open\('([0-9]+)', 131072\);$`)
	writePattern := regexp.MustCompile(`^SELECT pg_catalog[.]lowrite\(0, '\\x([0-9a-f]*)'\);$`)
	const closeLine = "SELECT pg_catalog.lo_close(0);"
	reader := bufio.NewScanner(input)
	reader.Buffer(make([]byte, 4096), restoreTOCMax)
	var current uint32
	var size int64
	var digest hash.Hash
	var result []ctr06BackupLargeObject
	for reader.Scan() {
		line := reader.Text()
		if match := openPattern.FindStringSubmatch(line); match != nil {
			oid, err := strconv.ParseUint(match[1], 10, 32)
			if err != nil || oid == 0 || current != 0 {
				return nil, errors.New("legacy large-object open is ambiguous")
			}
			current, size, digest = uint32(oid), 0, sha256.New()
		} else if match := writePattern.FindStringSubmatch(line); match != nil {
			if current == 0 {
				return nil, errors.New("legacy large-object data has no open object")
			}
			chunk, err := hex.DecodeString(match[1])
			if err != nil {
				return nil, errors.New("legacy large-object data is invalid")
			}
			_, _ = digest.Write(chunk)
			size += int64(len(chunk))
		} else if line == closeLine {
			if current == 0 {
				return nil, errors.New("legacy large-object close has no open object")
			}
			result = append(result, ctr06BackupLargeObject{OID: current, Bytes: size, SHA256: hex.EncodeToString(digest.Sum(nil))})
			current = 0
		} else if strings.HasPrefix(line, "SELECT pg_catalog.lo_open(") ||
			strings.HasPrefix(line, "SELECT pg_catalog.lowrite(") || strings.HasPrefix(line, "SELECT pg_catalog.lo_close(") {
			return nil, errors.New("legacy large-object SQL is unsupported")
		}
	}
	if reader.Err() != nil || current != 0 || len(result) != len(expected) {
		return nil, errors.New("legacy large-object data is incomplete")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].OID < result[j].OID })
	for i := range result {
		if result[i].OID != expected[i].OID {
			return nil, errors.New("legacy large-object data differs from its inventory")
		}
	}
	return result, nil
}
