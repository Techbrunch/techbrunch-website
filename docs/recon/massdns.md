# MassDNS

```text
python3 ./scripts/subbrute.py bitquark-subdomains-top100000.txt example.com | \
massdns -r resolvers.txt -t A -o S -w massdns-results.txt
```

