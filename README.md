# Using Visual Code to debug 
* step 1
```
go install -v github.com/haya14busa/goplay/cmd/goplay@v1.0.0
```
* step 2 add `.vscode/launch.json`
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}"
    }
  ]
}

```
* step 3
  * type `Ctrl + Shift + D`
  * press button `Launch`
  * press button `F5`

# Test
```bash
go mod init firewall_rules_converter
go mod tidy  
go run .
```
# Build
```bash
go mod init firewall_rules_converter
go mod tidy  
go build
```