package probe

import "os"

func readFile(path string) RawRead {
	info, statErr := os.Stat(path)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return RawRead{Exists: false}
		}
		return RawRead{Exists: false, Err: statErr}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return RawRead{Exists: true, Mode: info.Mode(), Err: err}
	}
	return RawRead{Exists: true, Content: string(b), Mode: info.Mode()}
}

func statPath(path string) RawRead {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return RawRead{Exists: false}
		}
		return RawRead{Exists: false, Err: err}
	}
	return RawRead{Exists: true, Mode: info.Mode()}
}
