<?php
class TLS
{
    const PARAM_TIMEOUT     = 1;

    private $__chunk        = 1024;
    private $__timeout      = 1;
    private $__host         = "0.0.0.0";
    private $__port         = 80;


    private $socket;
    private $connection;
    private $version = 0x0303;
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

    public function prepareConnection($connection=null)
    {
        if($connection==null) return false;

        require_once "12/handshake.php";
        $this->handshake = new srv\protocol\tls\tls12\Handshake();
        $this->handshake->handshake($connection);
    }

    public function recv($connection)
    {
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
    public function getRecordPackage($type=0x16,$record)
    {
        $package = pack("C*",$type,0x03,0x03);
        $package .= $this->getPackageSize($record,2);
        $package .= $record;
        return $package;
    }
    public function getPackageSize($package,$bytes=2)
    {
        $len = unpack("H*",pack("@".$bytes."N",strlen($package)))[1];
        $hex = "";
        for($i=1;$i<=$bytes*2;$i++){
            $hex = $len[strlen($len)-$i].$hex;
        }
        $size = hex2bin($hex);
        return $size;
    }
}
