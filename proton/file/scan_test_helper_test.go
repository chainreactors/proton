package file

import (
	"io/fs"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
)

func scanDir(s *Scanner, target string, callback func(Finding)) error {
	numWorkers := runtime.NumCPU()
	type job struct {
		path  string
		group *scanGroup
	}
	jobCh := make(chan job, numWorkers*256)
	var cbMu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				findings := s.ProcessFile(j.path, j.group)
				if len(findings) > 0 {
					atomic.AddInt64(&s.Stats.Findings, int64(len(findings)))
					cbMu.Lock()
					for _, f := range findings {
						callback(f)
					}
					cbMu.Unlock()
				}
			}
		}()
	}

	walkErr := parallelWalk(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if ShouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ext := filepath.Ext(path)
		if ShouldDenyExt(ext) {
			return nil
		}
		for _, group := range s.Groups {
			if !group.MatchesFile(path, ext) {
				continue
			}
			jobCh <- job{path: path, group: group}
		}
		return nil
	})
	close(jobCh)
	wg.Wait()
	return walkErr
}
