<?php
class tls
{
    const PARAM_TIMEOUT     = 1;

    private $__chunk        = 1024;
    private $__timeout      = 1;
    private $__host         = "0.0.0.0";
    private $__port         = 80;


    private $socket;
    private $connection;
    private $handshake;

    public function __construct($params=[])
    {
    }

    public function open($host,$port)
    {
        $this->__host = $host;
        $this->__port = $port;
        $this->socket = socket_create(AF_INET, SOCK_STREAM, 6);
        socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
        socket_bind($this->socket, $this->__host, $this->__port);
        socket_listen($this->socket, 10);
        return $this->socket;
    }

    public function recv($connection)
    {
        require_once "12/handshake.php";
        $this->handshake = new srv\tls\tls12\Handshake();
        $this->handshake->handshake($connection);
        return $this->handshake->recv($connection);
    }

    public function send($connection,$content)
    {
        $this->handshake->send($connection,$content);
    }

    public function setParam($key,$value)
    {
        switch($key){
            case self::PARAM_TIMEOUT:
                $this->__timeout = $value;
            break;
            default:
                throw new \Exception("Undefine parameter", 1);
        }
    }
}
