//go:build !linux

package store

func supportsOverlay() bool { return false }

func mountOverlay(lower []string, upper, work, dest string) error {
	return errNoOverlay
}

func mountOverlayRO(lower []string, dest string) error {
	return errNoOverlay
}

func (s *Store) unmount(path string) error { return nil }

var errNoOverlay = errNoOverlayImpl{}

type errNoOverlayImpl struct{}

func (errNoOverlayImpl) Error() string { return "store: overlayfs unavailable" }
