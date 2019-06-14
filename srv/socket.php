<?php

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

    private $context    = null;
    private $socket     = null;
    private $child      = false;

    public function __construct($context)
    {
        $this->context = $context;
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
        $proto = __DIR__."/protocols/".$this->__protocol."/".$this->__protocol.".php";
        if(file_exists($proto)){
            require_once $proto;
        }else{
            throw new \Exception("Protocol not suppored", 2);
        }
        if(class_exists($this->__protocol,false))
            $this->engine = new $this->__protocol();

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
            print "[ INFO ] Open socket...".PHP_EOL;
            $this->socket = $this->openServerSocket();
            print "[ OK ] Web server started!".PHP_EOL;
        }catch(Exception $e){
            print "[ FAIL ] Web server not started!".PHP_EOL;
            exit($e);
        }
        register_shutdown_function('shutdown',$this->socket);
        for($i = 0; $i < $this->__threads; $i++){
            $this->fork();
        }
        pcntl_signal(SIGINT,'sig_handler');
        while(pcntl_waitpid(0, $status) != -1):
                $status = pcntl_wexitstatus($status);
                print "[ FAIL ] Child ".$status." exited".PHP_EOL;
        endwhile;
        socket_close($this->socket);
        print "[ FAIL ] Socket closed!".PHP_EOL;
    }

    private function fork()
    {
        $pid = pcntl_fork();
        if($pid == 0){
            $this->child = true;
            $childpid = posix_getpid();
            print "[ OK ] Thread proccess started. pid:".$childpid.PHP_EOL;
            while ($this->run) {
                $connection = @socket_accept($this->socket);
                if(!$connection) continue;
                $content = "";
                $client = "";
                try{
                    $client = $this->engine->recv($connection,$content);
                    socket_getpeername($connection,$ip);
                    $execute = new execute($this->context,$client,$ip);
                    $content = $execute->getReturn();
                }catch(Exception $e){
                    print "Error: ".$e->getMessage()." in ".$e->getFile()." on line ".$e->getLine();
                    print PHP_EOL;
                    print $e->getTraceAsString();
                }catch(Error $e){
                    print "Error: ".$e->getMessage()." in ".$e->getFile()." on line ".$e->getLine();
                    print PHP_EOL;
                    print $e->getTraceAsString();
                }
                $this->engine->send($connection,$content);
                socket_close($connection);
            }
            exit();
        }
    }

    private function openServerSocket()
    {
        $this->socket = $this->engine->open($this->__host,$this->__port);
        if(!$this->socket)
            throw new Exception("Error starting server[{$errno}]: {$errstr}");
        print "[ OK ] Listening on {$this->__protocol}://{$this->__host}:{$this->__port}".PHP_EOL;
        return $this->socket;
    }

}
