<?php
namespace srv\protocol;
class TLS
{
    const HEADER_HANDSHAKE          = 0x16;
    const HEADER_APP_DATA           = 0x17;
    const HEADER_ALERT              = 0x15;
    const HEADER_CHANGE_CIPER_SPEC  = 0x14;

    private $__chunk                = 1024;
    private $__timeout              = 1;
    private $__host                 = "0.0.0.0";
    private $__port                 = 443;


    private $socket;
    private $connection;
    private $version = 0x0303;
    private $conf;
    private $handshake;
    public function __construct($context)
    {
        $this->conf = $context->srv->getConf();
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
        require_once 'handshake.php';
        $this->handshake = new \srv\protocol\tls\Handshake($connection,$this->conf);
    }

    public function recv($connection)
    {
        $get = true;
        $content = "";
        while($get){
            $pkgs = $this->getPackage($connection);
            foreach($pkgs as $pkg){
                switch(unpack("C*",$pkg['type'])[1]){
                    case self::HEADER_HANDSHAKE:
                        $this->handshake->rawPackage($pkg['data']);
                    break;
                    case self::HEADER_ALERT:
                        $this->alert($pkg['data']);
                    break;
                    case self::HEADER_CHANGE_CIPER_SPEC:
                    break;
                    case self::HEADER_APP_DATA:
                        $content .= $this->appData($pkg['data']);
                    break;
                    default:
                        socket_close($connection);
                        return false;
                }
            }
            if(count($pkgs)==0) $get = false;
        }
        if(strlen($content)==0) return false;

        return $content;
    }

    public function send($connection,$content)
    {
        $package = [];
        foreach(str_split($content, 8192) as $num => $chunk){
            $len = unpack("H*",pack("@8N",$num+1))[1];
            $hex = "";
            for($i=1;$i<=16;$i++) $hex = $len[strlen($len)-$i].$hex;
            $package[$num] = $this->handshake->getCipher()->getEncryptedMessage(null,null,$chunk,$hex,"170303");
            $package[$num] = TLS::getRecordPackage(0x17,$package[$num]);
        }
        $packages = implode("",$package);
        socket_write($connection,$packages);
    }

    private function appData($raw)
    {
        $decrypted = $this->handshake->getCipher()->getDecryptedMessage(null,$raw,"0000000000000001","170303");
        return $decrypted;
    }
    private function alert($raw)
    {

    }

    public static function getRecordPackage($type=0x16,$record)
    {
        $package = pack("C*",$type,0x03,0x03);
        $package .= self::getPackageSize($record,2);
        $package .= $record;
        return $package;
    }
    public static function getPackageSize($package,$bytes=2)
    {
        $len = unpack("H*",pack("@".$bytes."N",strlen($package)))[1];
        $hex = "";
        for($i=1;$i<=$bytes*2;$i++)
            $hex = $len[strlen($len)-$i].$hex;
        $size = hex2bin($hex);
        return $size;
    }
    private function getPackage($connection)
    {
        $done=false;
        $packages = [];
        $i=0;
        do {
            socket_set_option($connection, SOL_SOCKET, SO_RCVTIMEO, ['sec'=>0,'usec'=>55000]);
            socket_recv($connection,$packages[$i]['type'],1,MSG_WAITALL);

            if(strlen($packages[$i]['type'])==0){
                $done = true;
                unset($packages[$i]);
                continue;
            }
            socket_recv($connection,$packages[$i]['proto'],2,MSG_WAITALL);
            socket_recv($connection,$packages[$i]['lenght'],2,MSG_WAITALL);
            $packages[$i]['lenght'] = hexdec(bin2hex($packages[$i]['lenght']));
            socket_recv($connection,$packages[$i]['data'],$packages[$i]['lenght'],MSG_WAITALL);
            $i++;
        } while(!$done);
        return $packages;
    }
}
