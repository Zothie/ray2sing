package ray2sing_test

import (
	"net/http"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

func TestBeePass(t *testing.T) {
	ssconfURL := "https://s3.amazonaws.com/beedynconprd/ng4lf90ip01zstlyle4r0t56x1qli4cvmt2ws6nh0kdz1jpgzyedogxt3mpxfbxi.json"

	// This test depends on Beepass's live third-party config object. When the
	// object is gone or the network is unavailable the test must skip instead
	// of failing — the parser under test is not the thing that moved.
	resp, err := http.Get(ssconfURL)
	if err != nil {
		t.Skipf("live ssconf object unreachable, skipping: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("live ssconf object returned HTTP %d, skipping", resp.StatusCode)
	}

	url := "ssconf://s3.amazonaws.com/beedynconprd/ng4lf90ip01zstlyle4r0t56x1qli4cvmt2ws6nh0kdz1jpgzyedogxt3mpxfbxi.json#BeePass"

	// Define the expected JSON structure
	expectedJSON := `{
		"outbounds": [
			{
				"type": "shadowsocks",
				"tag": "BeePass § 0",
				"server": "beacomf.xyz",
				"server_port": 8080,
				"method": "chacha20-ietf-poly1305",
				"password": "nfzmfcBTcsj287NxNgMZDu"
			}
		]
	}`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
