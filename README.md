# Processor 
Beats processor for parsing Linux nftables log messages

## Building
Type make
That should build a shared library like filebeat-plugin-nftables-log-linux-amd64.so under Linux, or 
filebeat-plugin-nftables-log.dll under Windows

## Running
Run filebeat --plugin \<path to sharedlibrary\>

## Configuration

This processor supports three settings:

- "field": the name of the field where the nftables log is stored. By default, the value is "message"
- "marker": text before the firewall log. This is the "prefix" configured in nftables log statement.
- "target": the name of the field where the fields found are stored. By default, they are stored in the root (the value is "").
- "overwrite_keys": if "target" is defined, whether to overwrite it, when it already exists