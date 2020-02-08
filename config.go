package main

// NftablesLogConfig holds the configuration of the nftables log parser
type NftablesLogConfig struct {
	Field         string `config:"field"`
	Marker        string `config:"marker"`
	Target        string `config:"target"`
	OverwriteKeys bool   `config:"overwrite_keys"`
}

var defaultNftablesLogConfig = NftablesLogConfig{
	Field:  "message",
	Target: "",
	Marker: "INPUT_CON",
}
