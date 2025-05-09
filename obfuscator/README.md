# Payload obfuscator written in GoLang
Here you find the basic informations about the obfuscator.

**IMPORTANT:** This project is Work-in-Progress - WIP.

## Obfuscator Modules
**Note:** More modules for obfuscation will be added.

The current obfuscator provides the possiblity to obfuscatea/deobfuscate 
the payload to/from IPv4 format to hide it from the basic detection 
mechanisms. 

Flags to use:
```bash
# Obfuscate given payload
$ goloader --payload <PAYLOAD> --toIPv4

# Deobfuscate given payload
$ goloader --payloadFile <PATH-TO-FILE> --fromIPv4
```

## Helper Modules
The helper module provides the following helper functions:
 - GetContentFromFileWithChecks(filePath) -> Returns the whole file content 

More helpers will added by need.
