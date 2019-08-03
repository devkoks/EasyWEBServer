<?php
namespace srv\protocol;
class TCP
{
    const PARAM_TIMEOUT     = 1;

    private $__chunk        = 1024;
    private $__timeout      = 1;
    private $__host         = "0.0.0.0";
    private $__port         = 80;


    private $socket;
    private $connection;

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

    public function getHeaders($connection)
    {
        $done = false;
        $headers = "";
        while(!$done){
            $bytes = socket_recv($connection,$r_data,1,MSG_DONTWAIT);
            if($bytes>0) $headers .= $r_data;
            if(strlen($headers) > 4 && substr($headers,-4)=="\r\n\r\n")
                $done = true;
        }

        return $headers;
    }
    public function getBody($connection,$len)
    {
        socket_recv($connection,$r_data,$len,MSG_WAITALL);
        return $r_data;
    }


    public function recv($connection)
    {
        //socket_set_option($connection, SOL_SOCKET, SO_RCVTIMEO, ['sec'=>$this->__timeout,'usec'=>0]);
        $response = "";
        $done = false;
        while(!$done) {
            socket_clear_error($connection);
            $bytes = socket_recv($connection, $r_data, $this->__chunk, MSG_DONTWAIT);
            $lastError = socket_last_error($connection);
            if($lastError==35){
                if(substr(bin2hex($response),-4)=="0d0a"){
                    $done = true;
                }
            }elseif ($bytes === false) {
                if(substr(bin2hex($response),-4)=="0d0a"){
                    $done = true;
                }
            } elseif (intval($bytes) > 0) {
                $response .= $r_data;
            } else {
                $done = true;
            }
        }
        return $response;
    }

    public function send($connection,$content)
    {
        if($content!=""){
            $totalSent = 0;
            $i=0;
            $time=time();
            $oldChunk = 0;
            do{
                $Chunk = substr($content,$totalSent,$this->__chunk);
                $sent = socket_write($connection, $Chunk, $this->__chunk);
                $totalSent += $sent;
                if($totalSent == $oldChunk){
                    $i++;
                }else{
                    $oldChunk = $totalSent;
                    $i=0;
                    $time=time();
                }
            } while ($totalSent < strlen($content));
        }else{
            socket_write($connection, " ");
        }
    }
}
