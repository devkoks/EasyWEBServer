<?php
declare(ticks = 1);
function shutdown($socket=null){
    @socket_close($socket);
}
function sig_handler(){
    exit;
}
//register_shutdown_function('shutdown');
class srv
{
    private $__conf = [];
    private $__args = [];

    public function __construct()
    {
        $this->__conf = include "srv.conf.php";
        $this->__args = include "srv/arguments.php";
        include "srv/execute.php";
        include "srv/socket.php";
        include $this->__conf["start"]["dir"].$this->__conf["start"]["file"];
        print "[ INFO ] Starting web server...".PHP_EOL;
        $status = true;
        while($status){
            $this->socket();
            //More...
        }
    }

    public function getConf(){return $this->__conf;}

    private function socket()
    {
        $socket = new socket($this);
        $socket->configure("threads",$this->__conf["threads"]);
        $socket->configure("protocol",$this->__conf["protocol"]);
        $socket->configure("local_cert",$this->__conf["certificate"]);
        $socket->configure("host",$this->__conf["host"]);
        $socket->configure("port",$this->__conf["port"]);
        $socket->start();
    }

} new srv();
