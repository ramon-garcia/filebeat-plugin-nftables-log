package main

import (
	"bytes"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pkg/errors"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/processors"
)

// NftablesLogParser contains the data of a log parser processor
type NftablesLogParser struct {
	config NftablesLogConfig
}

var integerFields map[string]bool = map[string]bool{"LEN": true, "TOS": true, "PREC": true, "TTL": true, "ID": true, "SPT": true, "DPT": true, "WINDOW": true, "RES": true, "URGP": true, "UID": true, "GID": true}

func (f NftablesLogParser) String() string {
	b := new(bytes.Buffer)
	b.WriteString("nftables_log_parser=[")

	b.WriteString("field=")
	b.WriteString(f.config.Field)

	b.WriteString(", target=")
	b.WriteString(f.config.Target)

	b.WriteRune(']')

	return b.String()
}

// New creates a new nftables log parser processor
func New(c *common.Config) (processors.Processor, error) {
	fc := defaultNftablesLogConfig
	err := c.Unpack(&fc)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unpack nftables log parser config")
	}

	return &NftablesLogParser{
		config: fc,
	}, nil
}

// Run runs an event through a log parser processor
func (f *NftablesLogParser) Run(event *beat.Event) (*beat.Event, error) {
	msgField, _ := event.GetValue(f.config.Field)
	msgFieldStr, ok := msgField.(string)
	if !ok {
		return nil, errors.Errorf("unexpected type %T for nftables message field", msgField)
	}

	if f.config.Target != "" {
		newMap := common.MapStr{}
		f.parseNftablesLog(msgFieldStr, newMap)
		if !f.config.OverwriteKeys && f.config.Target != f.config.Field {
			if _, err := event.GetValue(f.config.Target); err == nil {
				return nil, errors.Errorf("target field %s already has a value. Set the overwrite_keys flag or drop/rename the field first", f.config.Target)
			}
		}
		event.PutValue(f.config.Target, newMap)
	} else {
		f.parseNftablesLog(msgFieldStr, event.Fields)
	}

	return event, nil
}

func (f *NftablesLogParser) parseNftablesLog(msg string, event common.MapStr) {
	pos := uint(0)
	if len(f.config.Marker) > 0 {
		posNew := strings.Index(msg, f.config.Marker)
		if posNew > 0 {
			pos = uint(posNew + len(f.config.Marker))
		} else {
			return
		}
	}
outer:
	for pos < uint(len(msg)) {

		// skip whitespace
		for {
			var width int
			c, width := utf8.DecodeRuneInString(msg[pos:])
			if width < 0 {
				break outer
			}
			if unicode.IsSpace(c) {
				pos += uint(width)
			} else {
				break
			}
			if pos >= uint(len(msg)) {
				break outer
			}
		}
		// look for next whitespace
		nextPos := pos
		for {
			var width int
			c, width := utf8.DecodeRuneInString(msg[nextPos:])
			if width < 0 {
				break outer
			}
			if !unicode.IsSpace(c) {
				nextPos += uint(width)
			} else {
				break
			}
			if nextPos >= uint(len(msg)) {
				break
			}
		}
		word := msg[pos:nextPos]
		equalPos := strings.IndexByte(word, '=')
		if equalPos < 0 {
			flags, existFlags := event.GetValue("flags")
			if existFlags != nil {
				flags = []string{word}
			} else {
				if flagsArr, ok := flags.([]string); ok {
					flags = append(flagsArr, word)
				}
			}
			event.Put("flags", flags)
		} else {
			if equalPos+1 < len(word) {
				key := word[0:equalPos]
				value := word[equalPos+1:]
				if _, ok := integerFields[key]; ok {
					valueInt64, err := strconv.ParseInt(value, 0, 32)
					valueInt := int(valueInt64)
					if err == nil {
						event.Put(key, valueInt)
					}
				} else {
					event.Put(key, value)
				}
			}
		}
		pos = nextPos
	}
}
