// Package storage provides filesystem-based message archiving using compressed tar.gz files.
package storage

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// AttachmentContent holds a single attachment for archive writing.
type AttachmentContent struct {
	Filename string
	Data     []byte // raw binary content
}

// MessageContent holds the content for writing an archive.
type MessageContent struct {
	BodyText    string
	BodyHTML    string
	HeadersJSON []byte // raw JSON of headers
	Attachments []AttachmentContent
}

// ContentHash returns a SHA-256 over the content MSNGR actually stored for a message:
// the body parts and each attachment, in a fixed order.
//
// It deliberately covers the stored content rather than the original RFC 5322 source,
// which MSNGR never fetches in full. It answers "has the archive changed since it was
// written?", not "does this match what the sender sent". Callers must leave the field
// empty when nothing is stored — an all-zero hash presented as tamper-evidence is worse
// than no hash, because someone will rely on it.
func ContentHash(c *MessageContent) string {
	if c == nil || (c.BodyText == "" && c.BodyHTML == "" && len(c.HeadersJSON) == 0 && len(c.Attachments) == 0) {
		return ""
	}

	h := sha256.New()
	writePart := func(label string, data []byte) {
		// Length-prefix each part so concatenation cannot be ambiguous.
		fmt.Fprintf(h, "%s:%d:", label, len(data))
		h.Write(data)
	}
	writePart("body.txt", []byte(c.BodyText))
	writePart("body.html", []byte(c.BodyHTML))
	writePart("headers.json", c.HeadersJSON)

	names := make([]string, 0, len(c.Attachments))
	byName := make(map[string][]byte, len(c.Attachments))
	for _, att := range c.Attachments {
		names = append(names, att.Filename)
		byName[att.Filename] = att.Data
	}
	sort.Strings(names)
	for _, name := range names {
		writePart("attachments/"+name, byName[name])
	}

	return hex.EncodeToString(h.Sum(nil))
}

// Store manages filesystem message archives.
type Store struct {
	basePath string
}

// NewStore creates a new Store rooted at basePath.
func NewStore(basePath string) *Store {
	return &Store{basePath: basePath}
}

// sanitizeMsgID replaces filesystem-unsafe characters in a message ID.
func sanitizeMsgID(msgID string) string {
	replacer := strings.NewReplacer(
		"<", "_",
		">", "_",
		":", "_",
		"/", "_",
		"\\", "_",
		"|", "_",
		"?", "_",
		"*", "_",
		" ", "_",
	)
	sanitized := replacer.Replace(msgID)
	// Collapse multiple underscores.
	for strings.Contains(sanitized, "__") {
		sanitized = strings.ReplaceAll(sanitized, "__", "_")
	}
	sanitized = strings.Trim(sanitized, "_")
	if sanitized == "" {
		sanitized = "unknown"
	}
	return sanitized
}

// archiveFilename returns a timestamped filename: YYYYMMDD-HHMMSS_<sanitized-msg-id>.tar.gz
func archiveFilename(msgID string) string {
	ts := time.Now().UTC().Format("20060102-150405")
	return ts + "_" + sanitizeMsgID(msgID) + ".tar.gz"
}

// ArchivePath returns the absolute archive path for a message (does not write).
func (s *Store) ArchivePath(accountEmail string, msgID string) string {
	return filepath.Join(s.basePath, accountEmail, archiveFilename(msgID))
}

// WriteMessage writes a tar.gz archive with body, headers, and attachments.
// It returns the relative archive path (email/YYYYMMDD-HHMMSS_msgID.tar.gz).
func (s *Store) WriteMessage(accountEmail string, msgID string, content *MessageContent) (string, error) {
	relPath := filepath.Join(accountEmail, archiveFilename(msgID))
	absPath := filepath.Join(s.basePath, relPath)

	// Create the directory if needed.
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create archive dir %s: %w", dir, err)
	}

	f, err := os.Create(absPath)
	if err != nil {
		return "", fmt.Errorf("create archive file %s: %w", absPath, err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	now := time.Now()

	// Helper to write a file entry into the tar.
	writeEntry := func(name string, data []byte) error {
		hdr := &tar.Header{
			Name:    name,
			Size:    int64(len(data)),
			Mode:    0o644,
			ModTime: now,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header %s: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("write tar data %s: %w", name, err)
		}
		return nil
	}

	if content.BodyText != "" {
		if err := writeEntry("body.txt", []byte(content.BodyText)); err != nil {
			return "", err
		}
	}
	if content.BodyHTML != "" {
		if err := writeEntry("body.html", []byte(content.BodyHTML)); err != nil {
			return "", err
		}
	}
	if len(content.HeadersJSON) > 0 {
		if err := writeEntry("headers.json", content.HeadersJSON); err != nil {
			return "", err
		}
	}
	for _, att := range content.Attachments {
		if err := writeEntry("attachments/"+att.Filename, att.Data); err != nil {
			return "", err
		}
	}

	return relPath, nil
}

// ReadBody extracts just body.txt and body.html from an archive.
func (s *Store) ReadBody(archivePath string) (text, html string, err error) {
	absPath := s.resolveArchivePath(archivePath)

	err = s.walkTar(absPath, func(name string, r io.Reader) error {
		switch name {
		case "body.txt":
			data, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			text = string(data)
		case "body.html":
			data, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			html = string(data)
		}
		return nil
	})
	return text, html, err
}

// ReadAttachment extracts a specific attachment by filename from an archive.
func (s *Store) ReadAttachment(archivePath, filename string) ([]byte, error) {
	absPath := s.resolveArchivePath(archivePath)
	target := "attachments/" + filename

	var result []byte
	err := s.walkTar(absPath, func(name string, r io.Reader) error {
		if name == target {
			data, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			result = data
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("attachment %q not found in archive %s", filename, archivePath)
	}
	return result, nil
}

// Delete removes an archive file.
func (s *Store) Delete(archivePath string) error {
	absPath := s.resolveArchivePath(archivePath)
	if err := os.Remove(absPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete archive %s: %w", absPath, err)
	}
	return nil
}

// DiskUsage returns total bytes used in the storage directory.
func (s *Store) DiskUsage() (int64, error) {
	var total int64
	err := filepath.Walk(s.basePath, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return 0, fmt.Errorf("walk storage path: %w", err)
	}
	return total, nil
}

// resolveArchivePath turns a relative archive path into an absolute one.
// If the path is already absolute, it is returned as-is.
func (s *Store) resolveArchivePath(archivePath string) string {
	if filepath.IsAbs(archivePath) {
		return archivePath
	}
	return filepath.Join(s.basePath, archivePath)
}

// walkTar opens a tar.gz file and calls fn for each entry.
func (s *Store) walkTar(absPath string, fn func(name string, r io.Reader) error) error {
	f, err := os.Open(absPath)
	if err != nil {
		return fmt.Errorf("open archive %s: %w", absPath, err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader %s: %w", absPath, err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry %s: %w", absPath, err)
		}
		if err := fn(hdr.Name, tr); err != nil {
			return err
		}
	}
	return nil
}
