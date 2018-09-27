<?php
class socket
{
    private $__protocol = "tcp";
    private $__host     = "0.0.0.0";
    private $__port     = "8000";
    private $__dir      = "./data";
    private $__tls_cert = "";

    private $__chunk    = 8194;

    private $context;

    public function __construct($context)
    {
        $this->context = $context;
    }

    public function configure($param,$value)
    {
        switch($param){
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

    public function server()
    {
        try{
            print "[ INFO ] Open socket...".PHP_EOL;
            $socket = $this->openServerSocket();
            print "[ OK ] Web server started!".PHP_EOL;
        }catch(Exception $e){
            print "[ FAIL ] Web server not started!".PHP_EOL;
            exit($e);
        }
        while ($connection = stream_socket_accept($socket,-1)) {
            $content = "";
            $client = "";
            try{
                stream_set_blocking($connection,false);
                while($client == "") $client = stream_get_contents($connection);
                $ip = stream_socket_get_name($connection,true);
                $ip = explode(":",$ip);
                $ip = $ip[0];
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
            $this->send($connection,$content);
            fclose($connection);
        }
        fclose($socket);
        print "[ FAIL ] Socket closed!".PHP_EOL;
    }

    private function send($connection,$data)
    {
        if($data!=""){
            $totalSent = 0;
            do{
                $Chunk = substr($data,$totalSent,$this->__chunk);
                $sent = fwrite($connection, $Chunk, $this->__chunk);
                $totalSent += $sent;
            } while ($totalSent < strlen($data));
        }else{
            fwrite($connection, " ");
        }
    }

    private function openServerSocket()
    {
        $socket = false;
        switch($this->__protocol){
            case "tcp":
                $socket = stream_socket_server("{$this->__protocol}://{$this->__host}:{$this->__port}", $errno, $errstr);
            break;
            case "tls":
                $context = stream_context_create([
                    "ssl"=>[
                        "local_cert"=>$this->__tls_cert,
                        "allow_self_signed"=>true,
                        "verify_peer"=>false
                    ]
                ]);
                $socket = stream_socket_server("{$this->__protocol}://{$this->__host}:{$this->__port}", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
            break;
            default:
                $socket = false;
        }
        if(!$socket)
            throw new Exception("Error starting server[{$errno}]: {$errstr}");
        print "[ OK ] Listening on {$this->__protocol}://{$this->__host}:{$this->__port}".PHP_EOL;
        return $socket;
    }

}
