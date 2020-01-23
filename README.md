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
	"REQUEST_TIME"=>1569808779,
	"HTTP_HEADERS"=> Array (
		"Accept-Encoding"=>"gzip, deflate, br",
		"User-Agent"=>"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"
	),
	"__SRV"=>Object(__SRV)
	"__IPC"=>Object(__IPC),
	"__EVENTS"=>Object(__EVENTS)
)
```
# Server objects
## __SRV
### setContent( string $content ) : void
Send a raw HTTP body

Example:
```php
$_SERVER['__SRV']->setContent("Hello World!");
```
### header( string $header ) : void
Send a raw HTTP header

Example:
```php
$_SERVER['__SRV']->header("Location: http://www.example.com/");
```
### status( int $status, string $description ) : void
Send HTTP status

Example:
```php
$_SERVER['__SRV']->status(200,'OK');
```
## __IPC
### isset( string $variable ) : bool
Check variable in shared memory

Example:
```php
$_SERVER['__IPC']->isset('bar');
```
### get( string $variable ) : mixed
Returns a variable from shared memory

Example:
```php
$_SERVER['__IPC']->get('bar');
```
### set( string $variable, mixed $value ) : void
Inserts or updates a variable in shared memory

Example:
```php
$_SERVER['__IPC']->set('bar','foo');
```
### send( int $type, string $msg ) : void
Send a message to a message queue

Example:
```php
$_SERVER['IPC']->send(1,'hello');
```
### recv( int $type ) : string
Receive a message from a message queue

Example:
```php
$_SERVER['__IPC']->recv(1);
```

## __EVENTS
### add( string $name, string $path, array $start ) : void
Add new event

Example:
```php
$_SERVER['__EVENTS']->add('bar','/path/to/file.php',[
	'object'=>'cron',
	'method'=>'init',
	'params'=>[]
]);
```
### addTimer( string $name, int $time [, bool $isPeriodic = true ] ) : void
Add timer to event

Example:
```php
$_SERVER['__EVENTS']->addTimer('bar',5,true);
```
### get( string $name ) : array
Get event information

Example:
```php
$_SERVER['__EVENTS']->get('bar');
```
### remove( string $name ) : void
Remove event

Example:
```php
$_SERVER['__EVENTS']->remove('bar');
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
