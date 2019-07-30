#!/usr/bin/php -d pcre.jit=0
<?php
declare(ticks = 1);
function shutdown($socket=null){
    @socket_close($socket);
}
function sig_handler(){
    exit;
}
class srv
{
    private $__conf = [];
    private $__args = [];
    private $status = true;

    public function __construct()
    {
	$this->__args = include "srv/arguments.php";	
	if(isset($this->__args['g']))
             $this->__conf = include $this->__args['g'];
	else
	     $this->__conf = include "srv.conf.php";
        include "srv/IPC.php";
        include "srv/execute.php";
        include "srv/socket.php";
        include $this->__conf["start"]["dir"].$this->__conf["start"]["file"];
        print "[ INFO ] Starting web server...".PHP_EOL;
        while($this->status){
            $this->socket();
            //More...
        }
    }

    public function getConf(){return $this->__conf;}

    private function socket()
    {
        $socket = new \srv\socket($this);
        $socket->configure("threads",$this->__conf["threads"]);
        $socket->configure("protocol",$this->__conf["protocol"]);
        $socket->configure("local_cert",$this->__conf['tls']["cert"]);
        $socket->configure("host",$this->__conf["host"]);
        $socket->configure("port",$this->__conf["port"]);
        if(isset($this->__args['t'])) $socket->configure("threads",$this->__args['t']);
        if(isset($this->__args['s'])) $socket->configure("protocol",$this->__args['s']);
        if(isset($this->__args['c'])) $socket->configure("local_cert",$this->__args['c']);
        if(isset($this->__args['h'])) $socket->configure("host",$this->__args['h']);
        if(isset($this->__args['p'])) $socket->configure("port",$this->__args['p']);
        $socket->start();
    }

} new srv();
