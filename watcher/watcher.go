// package watcher

// import (
// 	"context"
// 	"crypto/sha256"
// 	"encoding/hex"
// 	"io"
// 	"log"
// 	"os"
// 	"path/filepath"
// 	"strings"
// 	"syscall"
// 	"time"

// 	"github.com/fsnotify/fsnotify"
// 	"go.mongodb.org/mongo-driver/mongo"
// 	"go.mongodb.org/mongo-driver/mongo/options"
// )

// // Allowed file extensions to monitor
// var allowedExtensions = map[string]bool{
// 	".pdf":  true,
// 	".doc":  true,
// 	".docx": true,
// 	".ppt":  true,
// 	".pptx": true,
// }

// // MongoDB configuration
// const (
// 	MongoURI   = "mongodb://admin:adminpass@localhost:27017/"
// 	Database   = "filewatcher_db"
// 	Collection = "events"
// )

// // FileMetadata represents event data
// type FileMetadata struct {
// 	FileName         string    `bson:"file_name"`
// 	FullPath         string    `bson:"full_path"`
// 	EventType        string    `bson:"event_type"`
// 	Timestamp        time.Time `bson:"timestamp"`
// 	Size             int64     `bson:"size,omitempty"`
// 	LastModified     time.Time `bson:"last_modified,omitempty"`
// 	Created          time.Time `bson:"created,omitempty"`
// 	Accessed         time.Time `bson:"accessed,omitempty"`
// 	Permissions      string    `bson:"permissions,omitempty"`
// 	Checksum         string    `bson:"checksum,omitempty"`
// 	StreamedToServer bool      `bson:"streamed_to_server"`
// }

// type FileWatcher struct {
// 	watcher *fsnotify.Watcher
// 	root    string
// 	done    chan struct{}
// }

// func NewFileWatcher(rootPath string) (*FileWatcher, error) {
// 	watcher, err := fsnotify.NewWatcher()
// 	if err != nil {
// 		return nil, err
// 	}

// 	fw := &FileWatcher{
// 		watcher: watcher,
// 		root:    rootPath,
// 		done:    make(chan struct{}),
// 	}

// 	go fw.eventProcessor()

// 	// Walk the directory tree and add accessible directories
// 	err = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
// 		if err != nil {
// 			if os.IsPermission(err) {
// 				log.Printf("Skipping restricted directory: %s", path)
// 				return filepath.SkipDir
// 			}
// 			return err
// 		}

// 		if info.IsDir() {
// 			// Skip system directories
// 			if isSystemDirectory(path) {
// 				return filepath.SkipDir
// 			}

// 			// Check directory accessibility
// 			if err := checkAccess(path); err != nil {
// 				log.Printf("Skipping inaccessible directory: %s (%v)", path, err)
// 				return filepath.SkipDir
// 			}

// 			// Add directory to watcher
// 			if err := watcher.Add(path); err != nil {
// 				if os.IsPermission(err) {
// 					log.Printf("No permission to watch: %s", path)
// 					return nil
// 				}
// 				return err
// 			}
// 		}
// 		return nil
// 	})

// 	if err != nil {
// 		watcher.Close()
// 		return nil, err
// 	}

// 	return fw, nil
// }

// func (fw *FileWatcher) eventProcessor() {
// 	defer close(fw.done)

// 	// MongoDB client
// 	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(MongoURI))
// 	if err != nil {
// 		log.Fatal("Error connecting to MongoDB:", err)
// 	}
// 	defer client.Disconnect(context.TODO())

// 	collection := client.Database(Database).Collection(Collection)

// 	for {
// 		select {
// 		case event, ok := <-fw.watcher.Events:
// 			if !ok {
// 				return
// 			}
// 			fw.handleEvent(event, collection)

// 		case err, ok := <-fw.watcher.Errors:
// 			if !ok {
// 				return
// 			}
// 			log.Println("Watcher error:", err)

// 		case <-fw.done:
// 			return
// 		}
// 	}
// }

// func (fw *FileWatcher) handleEvent(event fsnotify.Event, collection *mongo.Collection) {
// 	// Check file extension
// 	ext := filepath.Ext(event.Name)
// 	if !allowedExtensions[ext] {
// 		return
// 	}

// 	// Handle directory creation
// 	if event.Op&fsnotify.Create == fsnotify.Create {
// 		info, err := os.Stat(event.Name)
// 		if err == nil && info.IsDir() {
// 			fw.watcher.Add(event.Name)
// 		}
// 	}

// 	// Handle delete/rename events separately
// 	if event.Op&fsnotify.Remove == fsnotify.Remove || event.Op&fsnotify.Rename == fsnotify.Rename {
// 		metadata := FileMetadata{
// 			FileName:         filepath.Base(event.Name),
// 			FullPath:         event.Name,
// 			EventType:        getEventType(event.Op),
// 			Timestamp:        time.Now(),
// 			StreamedToServer: false,
// 		}
// 		if err := insertFileEvent(metadata, collection); err != nil {
// 			log.Println("Error writing to DB:", err)
// 		}
// 		return
// 	}

// 	// For other operations, check if it's a file
// 	info, err := os.Stat(event.Name)
// 	if err != nil || info.IsDir() {
// 		return
// 	}

// 	metadata := FileMetadata{
// 		FileName:         filepath.Base(event.Name),
// 		FullPath:         event.Name,
// 		EventType:        getEventType(event.Op),
// 		Timestamp:        time.Now(),
// 		StreamedToServer: false,
// 	}

// 	// Collect metadata
// 	metadata.Size = info.Size()
// 	metadata.LastModified = info.ModTime()
// 	metadata.Permissions = info.Mode().String()

// 	// Windows timestamps
// 	if sys := info.Sys(); sys != nil {
// 		if stat, ok := sys.(*syscall.Win32FileAttributeData); ok {
// 			metadata.Created = time.Unix(0, stat.CreationTime.Nanoseconds())
// 			metadata.Accessed = time.Unix(0, stat.LastAccessTime.Nanoseconds())
// 		}
// 	}

// 	// Calculate checksum
// 	if checksum, err := computeChecksum(event.Name); err == nil {
// 		metadata.Checksum = checksum
// 	} else {
// 		log.Printf("Checksum error for %s: %v", event.Name, err)
// 	}

// 	if err := insertFileEvent(metadata, collection); err != nil {
// 		log.Println("Error writing to DB:", err)
// 	}
// }

// func insertFileEvent(metadata FileMetadata, collection *mongo.Collection) error {
// 	_, err := collection.InsertOne(context.TODO(), metadata)
// 	if err != nil {
// 		return err
// 	}
// 	log.Println("Event stored:", metadata)
// 	return nil
// }

// func computeChecksum(path string) (string, error) {
// 	file, err := os.Open(path)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer file.Close()

// 	hash := sha256.New()
// 	if _, err := io.Copy(hash, file); err != nil {
// 		return "", err
// 	}
// 	return hex.EncodeToString(hash.Sum(nil)), nil
// }

// func getEventType(op fsnotify.Op) string {
// 	switch {
// 	case op&fsnotify.Create != 0:
// 		return "CREATE"
// 	case op&fsnotify.Write != 0:
// 		return "MODIFY"
// 	case op&fsnotify.Remove != 0:
// 		return "DELETE"
// 	case op&fsnotify.Rename != 0:
// 		return "RENAME"
// 	default:
// 		return "UNKNOWN"
// 	}
// }

// func (fw *FileWatcher) Close() {
// 	close(fw.done)
// 	fw.watcher.Close()
// 	<-fw.done // Wait for processor to exit
// }

// func checkAccess(path string) error {
// 	file, err := os.Open(path)
// 	if err != nil {
// 		return err
// 	}
// 	file.Close()
// 	return nil
// }

// func isSystemDirectory(path string) bool {
// 	excluded := []string{
// 		"AppData\\Local\\Temp",
// 		"AppData\\Local\\Microsoft\\Windows\\INetCache",
// 		"AppData\\Local\\Microsoft\\Windows\\History",
// 	}

// 	for _, dir := range excluded {
// 		if strings.Contains(path, dir) {
// 			return true
// 		}
// 	}
// 	return false
// }

package watcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Allowed file extensions to monitor
var allowedExtensions = map[string]bool{
	".pdf":  true,
	".doc":  true,
	".docx": true,
	".ppt":  true,
	".pptx": true,
}

// MongoDB configuration
const (
	MongoURI   = "mongodb://admin:adminpass@localhost:27017/"
	Database   = "filewatcher_db"
	Collection = "events"
)

// FileMetadata represents event data
type FileMetadata struct {
	FileName         string    `bson:"file_name"`
	FullPath         string    `bson:"full_path"`
	EventType        string    `bson:"event_type"`
	Timestamp        time.Time `bson:"timestamp"`
	Size             int64     `bson:"size,omitempty"`
	LastModified     time.Time `bson:"last_modified,omitempty"`
	Created          time.Time `bson:"created,omitempty"`
	Accessed         time.Time `bson:"accessed,omitempty"`
	Permissions      string    `bson:"permissions,omitempty"`
	Checksum         string    `bson:"checksum,omitempty"`
	StreamedToServer bool      `bson:"streamed_to_server"`
}

type FileWatcher struct {
	watcher   *fsnotify.Watcher
	root      string
	done      chan struct{}
	mu        sync.Mutex
	lastEvent map[string]time.Time // Map to store the time of last event per file and event type
}

func NewFileWatcher(rootPath string) (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	fw := &FileWatcher{
		watcher:   watcher,
		root:      rootPath,
		done:      make(chan struct{}),
		lastEvent: make(map[string]time.Time),
	}

	go fw.eventProcessor()

	// Walk the directory tree and add accessible directories
	err = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				log.Printf("Skipping restricted directory: %s", path)
				return filepath.SkipDir
			}
			return err
		}

		if info.IsDir() {
			// Skip system directories
			if isSystemDirectory(path) {
				return filepath.SkipDir
			}

			// Check directory accessibility
			if err := checkAccess(path); err != nil {
				log.Printf("Skipping inaccessible directory: %s (%v)", path, err)
				return filepath.SkipDir
			}

			// Add directory to watcher
			if err := watcher.Add(path); err != nil {
				if os.IsPermission(err) {
					log.Printf("No permission to watch: %s", path)
					return nil
				}
				return err
			}
		}
		return nil
	})

	if err != nil {
		watcher.Close()
		return nil, err
	}

	return fw, nil
}

func (fw *FileWatcher) eventProcessor() {
	defer close(fw.done)

	// MongoDB client
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(MongoURI))
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}
	defer client.Disconnect(context.TODO())

	collection := client.Database(Database).Collection(Collection)

	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}
			fw.handleEvent(event, collection)

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			log.Println("Watcher error:", err)

		case <-fw.done:
			return
		}
	}
}

// shouldProcessEvent debounces events so that duplicate events within a threshold are ignored.
func (fw *FileWatcher) shouldProcessEvent(filePath, eventType string) bool {
	key := filePath + "_" + eventType
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if t, ok := fw.lastEvent[key]; ok && time.Since(t) < 1*time.Second {
		return false
	}
	fw.lastEvent[key] = time.Now()
	return true
}

func (fw *FileWatcher) handleEvent(event fsnotify.Event, collection *mongo.Collection) {
	// Check file extension
	ext := filepath.Ext(event.Name)
	if !allowedExtensions[ext] {
		return
	}

	// Determine event type and apply debouncing
	eventType := getEventType(event.Op)
	if !fw.shouldProcessEvent(event.Name, eventType) {
		return
	}

	// Handle directory creation (if a directory is created, add it to the watcher)
	if event.Op&fsnotify.Create == fsnotify.Create {
		info, err := os.Stat(event.Name)
		if err == nil && info.IsDir() {
			fw.watcher.Add(event.Name)
			// You may choose to return here if you don't want to record directory events
			return
		}
	}

	// Handle delete/rename events separately
	if event.Op&fsnotify.Remove == fsnotify.Remove || event.Op&fsnotify.Rename == fsnotify.Rename {
		metadata := FileMetadata{
			FileName:         filepath.Base(event.Name),
			FullPath:         event.Name,
			EventType:        eventType,
			Timestamp:        time.Now(),
			StreamedToServer: false,
		}
		if err := insertFileEvent(metadata, collection); err != nil {
			log.Println("Error writing to DB:", err)
		}
		return
	}

	// For other operations, check if it's a file
	info, err := os.Stat(event.Name)
	if err != nil || info.IsDir() {
		return
	}

	metadata := FileMetadata{
		FileName:         filepath.Base(event.Name),
		FullPath:         event.Name,
		EventType:        eventType,
		Timestamp:        time.Now(),
		StreamedToServer: false,
		Size:             info.Size(),
		LastModified:     info.ModTime(),
		Permissions:      info.Mode().String(),
	}

	// Windows timestamps
	if sys := info.Sys(); sys != nil {
		if stat, ok := sys.(*syscall.Win32FileAttributeData); ok {
			metadata.Created = time.Unix(0, stat.CreationTime.Nanoseconds())
			metadata.Accessed = time.Unix(0, stat.LastAccessTime.Nanoseconds())
		}
	}

	// Calculate checksum
	if checksum, err := computeChecksum(event.Name); err == nil {
		metadata.Checksum = checksum
	} else {
		log.Printf("Checksum error for %s: %v", event.Name, err)
	}

	if err := insertFileEvent(metadata, collection); err != nil {
		log.Println("Error writing to DB:", err)
	}
}

func insertFileEvent(metadata FileMetadata, collection *mongo.Collection) error {
	_, err := collection.InsertOne(context.TODO(), metadata)
	if err != nil {
		return err
	}
	log.Println("Event stored:", metadata)
	return nil
}

func computeChecksum(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func getEventType(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Create != 0:
		return "CREATE"
	case op&fsnotify.Write != 0:
		return "MODIFY"
	case op&fsnotify.Remove != 0:
		return "DELETE"
	case op&fsnotify.Rename != 0:
		return "RENAME"
	default:
		return "UNKNOWN"
	}
}

func (fw *FileWatcher) Close() {
	close(fw.done)
	fw.watcher.Close()
	<-fw.done // Wait for processor to exit
}

func checkAccess(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

func isSystemDirectory(path string) bool {
	excluded := []string{
		"AppData\\Local\\Temp",
		"AppData\\Local\\Microsoft\\Windows\\INetCache",
		"AppData\\Local\\Microsoft\\Windows\\History",
	}

	for _, dir := range excluded {
		if strings.Contains(path, dir) {
			return true
		}
	}
	return false
}
