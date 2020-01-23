# Dependencies
## PHP Version
PHP version >= 7.2

## PHP Modules

- posix
- pnctl
- sockets
- openssl
- posix_shm
- sysvmsg

# Variables

## $_SERVER

```php
Array (
	"SERVER_NAME"=>"syfy-host.com",
	"REMOTE_ADDR"=>"192.168.1.24",
	"PROTOCOL"=>"HTTP/1.1",
	"REQUEST_TYPE"=>"GET",
	"REQUEST_URI"=>"/",
	"REQUEST_TIME"=>1579808779,
	"HTTP_HEADERS"=> Array (
		"Accept-Encoding"=>"gzip, deflate, br",
		"User-Agent"=>"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"
	)
)
```

## $_POST
Default POST variable...
```php
Array (
	"key"=>"value",
	"bar"=>"foo"
)
```

## $_GET
Default GET variable...
```php
Array (
	"key"=>"value",
	"bar"=>"foo"
)
```
