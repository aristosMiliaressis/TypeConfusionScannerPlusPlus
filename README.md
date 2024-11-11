TypeConfusionScannerPlusPlus
==

url encoded array confusion payloads (original `key=value`)
```
key=value&key=value2
key[]=value&key[]=value2
key[0]=value&key[1]=value2
```

json type confusion payloads
```json
{"key":"1"}
{"bool_key":"true"}
```

json array confusion payloads (original `{"key":"value"}`)
```json
{"key":["value"]}
{"key":[["value"]]}
```

**ToDo**
- fix false positives due to first parameter parsing in urlencoded params
