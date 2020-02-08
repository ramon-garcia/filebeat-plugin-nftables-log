package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
)

const message = "2020-02-01T23:00:46.232980+01:00 maluma kernel: [539742.760933] OUTPUT_CONNECTION IN= OUT=eth0 SRC=192.168.1.222 DST=174.44.35.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=20827 DF PROTO=TCP SPT=42250 DPT=22 WINDOW=200 RES=0x00 SYN URGP=0 UID=2356 GID=2356"

func newTestNftablesLogParser(t testing.TB, field, marker, target string) *NftablesLogParser {
	if len(field) == 0 {
		field = defaultNftablesLogConfig.Field
	}
	c, err := common.NewConfigFrom(map[string]interface{}{
		"field":  field,
		"marker": marker,
		"target": target,
	})
	if err != nil {
		t.Fatal(err)
	}

	f, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return f.(*NftablesLogParser)
}

func TestSimple(t *testing.T) {
	processor := newTestNftablesLogParser(t, "message", "OUTPUT_CONNECTION", "")
	event := &beat.Event{Fields: common.MapStr{"message": message}}
	event, err := processor.Run(event)
	expectedEvent := common.MapStr{"message": message, "OUT": "eth0", "SRC": "192.168.1.222",
		"DST": "174.44.35.1", "LEN": 60, "TOS": 0, "PREC": 0,
		"TTL": 64, "ID": 20827, "flags": []string{"DF", "SYN"}, "PROTO": "TCP",
		"SPT": 42250, "DPT": 22, "WINDOW": 200, "RES": 0,
		"URGP": 0, "UID": 2356, "GID": 2356}
	if assert.NoError(t, err) {
		assert.Equal(t, expectedEvent, event.Fields, "Event processed with bad result")
	}
}
