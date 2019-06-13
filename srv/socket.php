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
                    if($this->__protocol=='tls'){
                        $tls = new tls();
                        $tls->handshake($connection);
                        $client = $tls->recv($connection);
                    }else{
                        $client = $this->recv($connection);
                    }
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
                if($this->__protocol=='tls'){
                    $tls->send($connection,$content);
                }else{
                    $this->send($connection,$content);
                }
                socket_close($connection);
            }
            exit();
        }
    }

    private function recv($connection)
    {
        socket_set_option($connection, SOL_SOCKET, SO_RCVTIMEO, ['sec'=>$this->__timeout,'usec'=>0]);
        $response = "";
        $done = false;
        while(!$done) {
            socket_clear_error($connection);
            $bytes = socket_recv($connection, $r_data, $this->__chunk, MSG_WAITALL);
            $lastError = socket_last_error($connection);
            if($lastError==35){
                $done = true;
            }elseif ($bytes === false) {
                $done = true;
            } elseif (intval($bytes) > 0) {
                $response .= $r_data;
            } else {
                $done = true;
            }
        }
        return $response;
    }

    private function send($connection,$data)
    {
        //socket_write($connection, " ");
        //stream_set_blocking($connection,true);
        if($data!=""){
            $totalSent = 0;
            $i=0;
            $time=time();
            $oldChunk = 0;
            do{
                $Chunk = substr($data,$totalSent,$this->__chunk);
                //$sent = @fwrite($connection, $Chunk, $this->__chunk);
                $sent = socket_write($connection, $Chunk, $this->__chunk);
                $totalSent += $sent;
                if($totalSent == $oldChunk){
                    $i++;
                }else{
                    $oldChunk = $totalSent;
                    $i=0;
                    $time=time();
                }
                //if($i==$this->__timeout or $time+10<time()) break;
            } while ($totalSent < strlen($data));
        }else{
            //@fwrite($connection, " ");
            socket_write($connection, " ");
        }
        //stream_set_blocking($connection,false);
    }

    private function openServerSocket()
    {
        //$socket = false;
        switch($this->__protocol){
            case "tcp":
                $this->socket = socket_create(AF_INET, SOCK_STREAM, 6);
                socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
                socket_bind($this->socket, $this->__host, $this->__port);
                socket_listen($this->socket, 10);
                //socket_set_nonblock($this->socket);
            break;
            case "tls":
                $context = stream_context_create([
                    "ssl"=>[
                        "local_cert"=>$this->__tls_cert,
                        "allow_self_signed"=>true,
                        "verify_peer"=>false
                    ]
                ]);
                $this->socket = socket_create(AF_INET, SOCK_STREAM, 6);
                socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
                socket_bind($this->socket, $this->__host, $this->__port);
                socket_listen($this->socket, 10);
            break;
            default:
                $socket = false;
        }
        //if(!$this->socket)
        //    throw new Exception("Error starting server[{$errno}]: {$errstr}");
        print "[ OK ] Listening on {$this->__protocol}://{$this->__host}:{$this->__port}".PHP_EOL;
        return $this->socket;
    }

}
