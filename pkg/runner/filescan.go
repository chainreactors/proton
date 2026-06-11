package runner

import (
	"io/fs"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/chainreactors/proton/proton/file"
	"github.com/charlievieth/fastwalk"
)

type fileJob struct {
	path  string
	group *file.ScanGroup
}

func walkAndScan(scanner *file.Scanner, target string, callback func(file.Finding)) error {
	numWorkers := runtime.NumCPU()
	jobCh := make(chan fileJob, numWorkers*256)
	var cbMu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				findings := scanner.ProcessFile(job.path, job.group)
				if len(findings) > 0 {
					atomic.AddInt64(&scanner.Stats.Findings, int64(len(findings)))
					cbMu.Lock()
					for _, f := range findings {
						callback(f)
					}
					cbMu.Unlock()
				}
			}
		}()
	}

	walkErr := fastwalk.Walk(nil, target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if file.ShouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ext := filepath.Ext(path)
		if file.ShouldDenyExt(ext) {
			return nil
		}
		for _, group := range scanner.Groups {
			if !group.MatchesFile(path, ext) {
				continue
			}
			jobCh <- fileJob{path: path, group: group}
		}
		return nil
	})
	close(jobCh)
	wg.Wait()
	return walkErr
}
