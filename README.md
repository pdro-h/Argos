# Argos
Network scanning, powered by Go

### Installation
```
git clone https://github.com/pdro-h/Argos.git
cd Argos
go build -o argos argos.go
```

Or run directly without building:
```
go run argos.go [options]
```

### Usage
```
argos [options]

Options:
  -host string    Target host or IP (required)
  -p    string    Port range (default: "1-1024")
  -t    int       Number of concurrent threads (default: 100)
  -timeout int    Connection timeout in milliseconds (default: 500)
  -v              Verbose mode — print results as they arrive
  -4              Force IPv4 resolution (default: true)
  -h              Show help
```

