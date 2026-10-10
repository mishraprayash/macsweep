package macos

import "testing"

func TestParseOpenFiles(t *testing.T) {
	out := []byte("p10\ncnode\nfcwd\nn/Users/me/code/web\nftxt\nn/Users/me/code/web/node_modules/.bin/esbuild\nf5\nnlocalhost:3000\n" +
		"p11\ncsweep\nf3\nn/Users/me/Library/Caches/sweep/last-scan.gob.gz\n" +
		"p12\ncSlack Helper\nf9\nn/Users/me/Library/Caches/com.tinyspeck.slackmacgap/Cache.db\n")
	o := ParseOpenFiles(out, 11)
	for path, want := range map[string]string{
		"/Users/me/code/web/node_modules":                     "node",
		"/Users/me/code/web":                                  "node",
		"/Users/me/Library/Caches/com.tinyspeck.slackmacgap":  "Slack Helper",
		"/users/me/library/caches/COM.TINYSPECK.SLACKMACGAP/": "Slack Helper",
	} {
		if got, ok := o.Under(path); !ok || got != want {
			t.Errorf("Under(%s) = %q, %v; want %q", path, got, ok, want)
		}
	}
	for _, path := range []string{
		"/Users/me/code/web/node_modules/react", // a sibling of what is open
		"/Users/me/code/we",                     // a prefix, not a parent
		"/Users/me/Library/Caches/sweep",        // only sweep itself has it open
	} {
		if got, ok := o.Under(path); ok {
			t.Errorf("Under(%s) = %q, want nothing", path, got)
		}
	}
	if _, ok := (*OpenFiles)(nil).Under("/x"); ok {
		t.Error("nil OpenFiles reported an open file")
	}
}
