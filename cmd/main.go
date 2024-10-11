package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"log/slog"
	"slices"
	"sync"
	"time"
)

const workerCount = 200

var mode int

func mono(asciiSet []rune, hash_slice []string, start_time *time.Time) {
	for _, ch1 := range asciiSet {
		for _, ch2 := range asciiSet {
			for _, ch3 := range asciiSet {
				for _, ch4 := range asciiSet {
					for _, ch5 := range asciiSet {
						pass := string([]rune{ch1, ch2, ch3, ch4, ch5})
						md5_hasher := md5.New()
						md5_hasher.Write([]byte(pass))
						test_hash_md5 := hex.EncodeToString(md5_hasher.Sum(nil))

						sha256_hasher := sha256.New()
						sha256_hasher.Write([]byte(pass))
						test_hash_sha256 := hex.EncodeToString(sha256_hasher.Sum(nil))

						if slices.Contains(hash_slice, test_hash_md5) {
							hash := slices.Index(hash_slice, test_hash_md5)
							curr_time := time.Now()
							diff := curr_time.Sub(*start_time)
							slog.Info("MD5", "hash", hash, "password", pass, "time", diff.Seconds())
						}
						if slices.Contains(hash_slice, test_hash_sha256) {
							hash := slices.Index(hash_slice, test_hash_sha256)
							curr_time := time.Now()
							diff := curr_time.Sub(*start_time)
							slog.Info("SHA256", "hash", hash, "password", pass, "time", diff.Seconds())
						}
					}
				}
			}
		}
	}
}

func worker(passChan <-chan string, hash_slice []string, start_time *time.Time, wg *sync.WaitGroup) {
	defer wg.Done()

	for pass := range passChan {

		md5_hasher := md5.New()
		md5_hasher.Write([]byte(pass))
		test_hash_md5 := hex.EncodeToString(md5_hasher.Sum(nil))

		sha256_hasher := sha256.New()
		sha256_hasher.Write([]byte(pass))
		test_hash_sha256 := hex.EncodeToString(sha256_hasher.Sum(nil))

		if slices.Contains(hash_slice, test_hash_md5) {
			hash := slices.Index(hash_slice, test_hash_md5)
			curr_time := time.Now()
			diff := curr_time.Sub(*start_time)
			slog.Info("MD5", "hash", hash, "password", pass, "time", diff.Seconds())
		}
		if slices.Contains(hash_slice, test_hash_sha256) {
			hash := slices.Index(hash_slice, test_hash_sha256)
			curr_time := time.Now()
			diff := curr_time.Sub(*start_time)
			slog.Info("SHA256", "hash", hash, "password", pass, "time", diff.Seconds())
		}
	}
}

func init() {
	flag.IntVar(&mode, "mode", 1, "1 - with gorutines, 2 - without gorutines")
	flag.Parse()
}

func main() {
	hash_slice := []string{"1115dd800feaacefdf481f1f9070374a2a81e27880f187396db67958b207cbad", "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b", "74e1bb62f8dabb8125a58852b63bdf6eaef667cb56ac7f7cdba6d7305c50a22f", "7a68f09bd992671bb3b19a5e70b7827e"}
	var asciiSet []rune
	for i := 97; i <= 122; i++ {
		asciiSet = append(asciiSet, rune(i))
	}

	var wg sync.WaitGroup
	passChan := make(chan string, workerCount)
	start_time := time.Now()

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(passChan, hash_slice, &start_time, &wg)
	}

	if mode == 1 {
		for _, ch1 := range asciiSet {
			for _, ch2 := range asciiSet {
				for _, ch3 := range asciiSet {
					for _, ch4 := range asciiSet {
						for _, ch5 := range asciiSet {
							pass := string([]rune{ch1, ch2, ch3, ch4, ch5})
							passChan <- pass
						}
					}
				}
			}
		}
		close(passChan)
		wg.Wait()
	}

	if mode == 2 {
		mono(asciiSet, hash_slice, &start_time)
	}
	log.Println("Done")
}
