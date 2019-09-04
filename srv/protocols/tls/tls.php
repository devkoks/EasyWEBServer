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
    private $close = false;
    private $decrypted_buff = "";
    public function __construct($context)
    {
        $this->conf = $context->srv->getConf();
        slog("INFO","Starting TLS module...");
        if(!file_exists($this->conf['tls']['priv']) or !file_exists($this->conf['tls']['cert'])){
            slog("ERROR","Certificate not found");
            slog("INFO","Creating certificate...");
            $privateKey = openssl_pkey_new(["private_key_bits" => 2048,"private_key_type" => OPENSSL_KEYTYPE_RSA]);
            $csr = openssl_csr_new(['commonName' => gethostname()], $privateKey, ['digest_alg' => 'sha256', 'req_extensions' => 'v3_req']);
            openssl_pkey_export($privateKey,$keyOut);
            $x509 = openssl_csr_sign($csr, null, $privateKey, 3600, ['digest_alg' => 'sha256', 'x509_extensions' => 'v3_ca'],time());
            openssl_x509_export($x509, $crtOut);
            switch($this->conf['tls']['auto-create-cert']['generate-type']){
                case "zfs":
                zfs_mount($this->conf['tls']['auto-create-cert']['zfs']['dataset']);
                $zroot = zfs_ds_list(['mountpoint']);
                $zroot = $zroot[$this->conf['tls']['auto-create-cert']['zfs']['dataset']]['mountpoint'];
                if(!file_exists(dirname("/etc".$this->conf['tls']['auto-create-cert']['zfs']['key-path'])))
                    mkdir(dirname("/etc".$this->conf['tls']['auto-create-cert']['zfs']['key-path']),0600,true);
                if(!file_exists(dirname("/etc".$this->conf['tls']['auto-create-cert']['zfs']['cert-path'])))
                    mkdir(dirname("/etc".$this->conf['tls']['auto-create-cert']['zfs']['cert-path']),0600,true);
                $fpriv = fopen("/etc".$this->conf['tls']['auto-create-cert']['zfs']['key-path'],'w');
                $fcert = fopen("/etc".$this->conf['tls']['auto-create-cert']['zfs']['cert-path'],'w');
                fwrite($fpriv, $keyOut);
                fwrite($fcert, $crtOut);
                fclose($fpriv);
                fclose($fcert);
                if(!file_exists(dirname($zroot.$this->conf['tls']['auto-create-cert']['zfs']['key-path'])))
                    mkdir(dirname($zroot.$this->conf['tls']['auto-create-cert']['zfs']['key-path']),0600,true);
                if(!file_exists(dirname($zroot.$this->conf['tls']['auto-create-cert']['zfs']['cert-path'])))
                    mkdir(dirname($zroot.$this->conf['tls']['auto-create-cert']['zfs']['cert-path']),0600,true);
                copy("/etc".$this->conf['tls']['auto-create-cert']['zfs']['key-path'],$zroot.$this->conf['tls']['auto-create-cert']['zfs']['key-path']);
                copy("/etc".$this->conf['tls']['auto-create-cert']['zfs']['cert-path'],$zroot.$this->conf['tls']['auto-create-cert']['zfs']['cert-path']);
                zfs_unmount($this->conf['tls']['auto-create-cert']['zfs']['dataset']);
                break;
            }
            $fpriv = fopen($this->conf['tls']['auto-create-cert']['fs']['key-path'],'w');
            $fcert = fopen($this->conf['tls']['auto-create-cert']['fs']['cert-path'],'w');
            fwrite($fpriv, $keyOut);
            fwrite($fcert, $crtOut);
            fclose($fpriv);
            fclose($fcert);

            slog("INFO","Certificate created!");
        }
    }

    public function open($host,$port)
    {
        $this->__host = $host;
        $this->__port = $port;
        $this->socket = socket_create(AF_INET, SOCK_STREAM, 6);
        socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
        socket_bind($this->socket, $this->__host, $this->__port);
        socket_listen($this->socket, 10);
        socket_set_nonblock($this->socket);
        return $this->socket;
    }

    public function prepareConnection($connection=null)
    {
        if($connection==null) return false;
        require_once 'handshake.php';
        $this->handshake = new \srv\protocol\tls\Handshake($connection,$this->conf);
    }

    public function getHeaders($connection)
    {
        $headers = $this->recv($connection,"\r\n\r\n");
        return $headers;
    }
    public function getBody($connection,$len)
    {
        $get = true;
        if(strlen($this->decrypted_buff)>=$len) return $this->decrypted_buff;
        while($get){
            $pkg = $this->getPackage($connection);
            if(unpack("C*",$pkg['type'])[1]==self::HEADER_APP_DATA){
                $this->decrypted_buff .= $this->appData($pkg['data']);
                if(strlen($this->decrypted_buff)>=$len){
                    $get = false;
                    return $this->decrypted_buff;
                }
            }
        }
        return $this->decrypted_buff;
    }

    public function recv($connection,$end_point=null)
    {
        $get = true;
        $content = "";
        while($get){
            $pkg = $this->getPackage($connection);
            //var_dump(bin2hex($pkg['type']));
            if($pkg === false){
                $get = false;
                continue;
            }
            switch(unpack("C*",$pkg['type'])[1]){
                case self::HEADER_HANDSHAKE:
                    $this->handshake->rawPackage($pkg['data']);
                    $this->close = false;
                break;
                case self::HEADER_ALERT:
                    $this->alert($pkg['data']);
                break;
                case self::HEADER_CHANGE_CIPER_SPEC:
                break;
                case self::HEADER_APP_DATA:
                    $content .= $this->appData($pkg['data']);
                    if($end_point!=null){
                        $i=0;
                        while(false !== ($buf = substr($content,$i,strlen($end_point)))){
                            if($buf==$end_point){
                                $get = false;
                                $this->decrypted_buff = substr($content,$i+4,strlen($content)-$i);
                                return substr($content,0,$i+1);
                            }
                            $i++;
                        }
                    }
                break;
                case "":
                    $this->close = false;
                break;
                default:
                    //socket_close($connection);
                    return false;
            }
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
        socket_set_option($connection, SOL_SOCKET, SO_SNDTIMEO, ['sec'=>30,'usec'=>0]);
        //var_dump($content);
        socket_write($connection,$packages);
    }

    private function appData($raw)
    {
        $decrypted = $this->handshake->getCipher()->getDecryptedMessage(null,$raw,"0000000000000001","170303");
        return $decrypted;
    }
    private function alert($raw)
    {
        //$decrypted = $this->handshake->getCipher()->getDecryptedMessage(null,$raw,"0000000000000001","170303");
        $alert = unpack("C*",$raw);
        switch($alert[2]){
            case 0x00:
                $this->close = true;
            break;
        }
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
        if($this->close) return false;
        $package = [];
        socket_recv($connection,$packages['type'],1,MSG_WAITALL);

        if(strlen($packages['type'])==0){
            unset($packages);
            return false;
        }
        socket_recv($connection,$packages['proto'],2,MSG_WAITALL);
        socket_recv($connection,$packages['lenght'],2,MSG_WAITALL);
        $len = $packages['lenght'];
        $packages['lenght'] = hexdec(bin2hex($packages['lenght']));
        socket_recv($connection,$packages['data'],$packages['lenght'],MSG_WAITALL);
        return $packages;
    }
}
