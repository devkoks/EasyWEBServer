#!/usr/bin/php
<?php
declare(ticks = 1);

function shutdown($socket=null){
    //@socket_close($socket);
}
function sig_handler(){
    exit;
}
class srv
{
    private $__conf = [];
    private $__args = [];
    private $__stag = [];
    private $status = true;

    const SRV_GRACEFUL = 8;
    const SRV_SHUTDOWN = 9;
    const SRV_ESUCCESS = 23;

    public function __construct()
    {
    	$this->__args = include "srv/arguments.php";
    	if(isset($this->__args['g']))
                 $this->__conf = include $this->__args['g'];
    	else
	       $this->__conf = include "srv/srv.conf.php";

        $_SERVER["CONF"] = $this->__conf;
        $_SERVER["LOGS_ENABLE"] = false;
      	error_reporting($this->__conf['error_reporting']);
        if(isset($this->__args['d'])) $_SERVER["LOGS_ENABLE"] = true;
        include "srv/log.php";
        include "srv/IPC.php";
        include "srv/execute.php";
        include "srv/Events.php";
        include "srv/socket.php";
        include $this->__conf["start"]["dir"].$this->__conf["start"]["file"];
        slog("INFO","Starting web server...");
        if(isset($this->__args['t'])) $this->__conf["threads"] = $this->__args['t'];
        if(isset($this->__args['s'])) $this->__conf["protocol"] = $this->__args['s'];
        if(isset($this->__args['c'])) $this->__conf["local_cert"] = $this->__args['c'];
        if(isset($this->__args['h'])) $this->__conf["host"] = $this->__args['h'];
        if(isset($this->__args['p'])) $this->__conf["port"] = $this->__args['p'];
        if(isset($this->__args['P'])) $this->__conf['pid'] = $args['P'];
        file_put_contents($this->__conf['pid'],posix_getpid());
        while($this->status){
            $this->socket();
            //More...
        }
        if(file_exists($this->__conf['pid']))unlink($this->__conf['pid']);
    }

    public function stop()
    {
        $this->status = false;
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
        $socket->start();
    }

}

if(isset($argv[1])){
    switch($argv[1]){
        case "start":
            (pcntl_fork()==0) ? new srv() : exit();
        break;
        case "stop":
            $conf = include "srv/srv.conf.php";
            $args = include "srv/arguments.php";
            if(isset($args['P'])) $conf['pid'] = $args['P'];
            $id = (file_exists($conf['pid']))?file_get_contents($conf['pid']):1;
            $msg = msg_get_queue(ftok(__DIR__.'/srv/IPC.php','s'),0444);
            msg_send($msg,$id,srv::SRV_SHUTDOWN);
        break;
        case "restart":
        break;
        default:
            new srv();
    }
}
