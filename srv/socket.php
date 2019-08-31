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
        socket_close($this->socket);
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
        for($i = 0; $i < $this->__threads; $i++){
            $this->fork();
        }
        pcntl_signal(SIGINT,'sig_handler');
        while(pcntl_waitpid(0, $status) != -1){
            $status = pcntl_wexitstatus($status);
            slog("FAIL","Child ".$status." exited");
        }
        $_SERVER['__IPC']->close();
        socket_close($this->socket);
        slog("FAIL","Socket closed!");
    }

    private function fork()
    {
        $pid = pcntl_fork();
        if($pid != 0) return;
        $childpid = posix_getpid();
        slog("OK","Thread proccess started. pid:".$childpid);
        $count = 0;
        while ($this->run) {
            $connection = @socket_accept($this->socket);
            while(pcntl_waitpid(0, $status, WNOHANG) != -1)
                $status = pcntl_wexitstatus($status);
            if(!$connection) continue;
            $count++;
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
                    continue;
                }
                if(isset($headers["Content-Length"]) && $headers["Content-Length"]>0)
                    $client .= $this->engine->getBody($connection,$headers["Content-Length"]);
                if($client === false){
                    if(get_resource_type($connection)=="Socket")
                        socket_close($connection);
                    continue;
                }
                socket_getpeername($connection,$ip);
                print "[Num:".$count.",fork:".$childpid."]-->Request[".$ip."]".PHP_EOL;
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
            socket_close($connection);
        }
        exit();

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
