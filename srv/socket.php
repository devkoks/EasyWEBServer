<?php
namespace srv;

class socket
{
    private $__threads  = 3;
    private $__protocol = "tcp";
    private $__host     = "0.0.0.0";
    private $__port     = "8000";
    private $__dir      = "./data";
    private $__tls_cert = "";

    private $__chunk    = 1024;
    private $__timeout  = 1;

    public $run         = true;

    public $srv         = null;
    private $socket     = null;

    private $childs     = [];
    private $parent     = null;

    public function __construct($context)
    {
        $this->srv = $context;
    }

    public function configure($param,$value)
    {
        switch($param){
            case "threads":
                $this->__threads = $value;
            break;
            case "protocol":
                $this->__protocol = $value;
            break;
            case "host":
                $this->__host = $value;
            break;
            case "port":
                $this->__port = $value;
            break;
            case "ROOT_DOCUMENT":
                $this->__dir = $value;
            break;
            case "local_cert":
                $this->__tls_cert = $value;
            break;
            default:
                return false;
        }
        return true;
    }

    public function start()
    {
        $protocol = '\srv\protocol\\'.strtoupper($this->__protocol);
        $proto = __DIR__."/protocols/".$this->__protocol."/".$this->__protocol.".php";
        if(file_exists($proto)){
            require_once $proto;
        }else{
            slog("ERROR","Protocol not suppored");
        }
        if(class_exists($protocol,false))
            $this->engine = new $protocol($this);

        $this->server();
    }
    public function stop()
    {
        $this->run = false;
    }

    public function server()
    {
        try{
            slog("INFO","Open socket...");
            $this->socket = $this->openServerSocket();
            slog("OK","Web server started!");
        }catch(Exception $e){
            slog("FAIL","Web server not started!");
            exit($e);
        }
        register_shutdown_function('shutdown',$this->socket);


        $_SERVER['__IPC'] = new IPC();
        $_SERVER['__EVENTS'] = new Events();
        for($i = 0; $i < $this->__threads; $i++){
            $this->childs[$this->fork()] = true;
        }
        pcntl_signal(SIGINT,'sig_handler');
        pcntl_signal(SIGTERM,'sig_handler');
        $state = true;
        while($state){
            usleep(50000);
            $_SERVER['__EVENTS']->execute();
            $id = (file_exists($this->srv->getConf()['pid']))?posix_getpid():1;
            $recv = $_SERVER['__IPC']->recv($id);
            if(!empty($recv)){
                switch($recv){
                    case \srv::SRV_SHUTDOWN:
                        print "Shutdown server...".PHP_EOL;
                        $this->stop();
                        $this->stopThreads();
                        $this->srv->stop();
                    break;
                    case \srv::SRV_SHUTDOWN:
                        $this->stop();
                    break;
                }
            }
            $pid = pcntl_waitpid(-1,$status,WNOHANG);
            if($pid > 0){
                unset($this->childs[$pid]);
                $status = pcntl_wexitstatus($status);
                /*if($status != \srv::SRV_SHUTDOWN){
                    $this->childs[$this->fork()] = true;
                }*/
                if($status!=\srv::SRV_ESUCCESS)
                    slog(($status!=\srv::SRV_SHUTDOWN)?"FAIL":"OK","Child ".$status." exited");
            }
            if(count($this->childs)==0) $state = false;
        }
        $_SERVER['__IPC']->close();
        socket_close($this->socket);
        slog(($this->run)?"FAIL":"OK","Socket closed!");
    }

    private function stopThreads()
    {
        reset($this->childs);
        while(count($this->childs)>0){
            usleep(10000);
            $pid = key($this->childs);
            $_SERVER['__IPC']->send($pid,\srv::SRV_SHUTDOWN);
            $pidr = pcntl_waitpid($pid,$status,WNOHANG);
            if($pidr>0){
                slog("OK","Child ".$pidr." exited");
                unset($this->childs[$pidr]);
                reset($this->childs);
            }
        }
    }

    private function fork()
    {
        $pid = pcntl_fork();
        if($pid != 0) return $pid;
        $childpid = posix_getpid();
        slog("OK","Thread proccess started. pid:".$childpid);
        while ($this->run) {
            usleep(5000);
            $connection = @socket_accept($this->socket);
            if(pcntl_waitpid(0, $status, WNOHANG) != -1) $status = pcntl_wexitstatus($status);
            $__SIGNAL = $_SERVER['__IPC']->recv(posix_getpid());
            if(!empty($__SIGNAL)){
                switch($__SIGNAL){
                    case \srv::SRV_SHUTDOWN:
                        $this->stop();
                        $this->srv->stop();
                    break;
                    case \srv::SRV_GRACEFUL:
                        $this->stop();
                        $this->srv->stop();
                    break;
                }
            }
            if(!$connection) continue;
            $proccess = pcntl_fork();
            if($proccess == 0){
                $this->connection($connection);
                exit(1);
            }else{
                pcntl_waitpid($proccess,$status);
                pcntl_wexitstatus($status);
                socket_close($connection);
            }
        }
        $code = 0;
        switch($__SIGNAL){
            case \srv::SRV_SHUTDOWN:
                $code = \srv::SRV_SHUTDOWN;
            break;
            case SRV_GRACEFUL:
                $code = \srv::SRV_GRACEFUL;
            default:
                $code = 0;
        }
        exit($code);
    }
    private function connection($connection)
    {
        $content = "";
        $client = "";
        try{
            if(method_exists($this->engine,"prepareConnection"))
                $this->engine->prepareConnection($connection);
            $headers = $this->engine->getHeaders($connection);
            $client .= $headers."\r\n\r\n";
            $headers = execute::parseHeaders($headers);
            if(count($headers)==0){
                socket_close($connection);
                return false;
            }
            if(isset($headers["Content-Length"]) && $headers["Content-Length"]>0)
                $client .= $this->engine->getBody($connection,$headers["Content-Length"]);
            if($client === false){
                if(get_resource_type($connection)=="Socket")
                    socket_close($connection);
                return false;
            }
            socket_getpeername($connection,$ip);
            $execute = new execute($this->srv,$client,$ip,$connection);
            $content = $execute->getReturn();
            unset($execute);
        }catch(Exception $e){
            slog("ERROR",$e->getMessage()." in ".$e->getFile()." on line ".$e->getLine().
            PHP_EOL.
            $e->getTraceAsString());
        }catch(Error $e){
            slog("ERROR",$e->getMessage()." in ".$e->getFile()." on line ".$e->getLine().
            PHP_EOL.
            $e->getTraceAsString());
        }catch(ErrorException $e){
            slog("ERROR",$e->getMessage()." in ".$e->getFile()." on line ".$e->getLine().
            PHP_EOL.
            $e->getTraceAsString());
        }
        $this->engine->send($connection,$content);
        return true;
    }

    private function openServerSocket()
    {
        $this->socket = $this->engine->open($this->__host,$this->__port);
        if(!$this->socket)
            throw new Exception("Error starting server[{$errno}]: {$errstr}");
        slog("OK","Listening on {$this->__protocol}://{$this->__host}:{$this->__port}");
        return $this->socket;
    }

}
