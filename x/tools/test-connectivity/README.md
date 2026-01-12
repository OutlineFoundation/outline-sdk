# Connectivity Test

This app illustrates the use of the Shadowsocks transport to resolve a domain name over TCP or UDP.

Example:
```
# From https://www.reddit.com/r/outlinevpn/wiki/index/prefixing/
KEY=ss://ENCRYPTION_KEY@HOST:PORT/
COLLECTOR_URL=https://collector.example.com/metrics
for PREFIX in POST%20 HTTP%2F1.1%20 %05%C3%9C_%C3%A0%01%20 %16%03%01%40%00%01 %13%03%03%3F %16%03%03%40%00%02; do
  go run go run golang.getoutline.org/sdk/x/tools/test-connectivity@latest -transport="$KEY?prefix=$PREFIX" -proto tcp -resolver 8.8.8.8 -report-to $COLLECTOR_URL -report-success-rate 0.2 -report-failure-rate 1.0 && echo Prefix "$PREFIX" works!
done
```
