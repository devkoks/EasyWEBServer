<?php
namespace srv\protocol\tls;

use \srv\protocol\TLS;

class Handshake
{

    const HEADER_CLIENTHELLO            = 0x01;
    const HEADER_SERVERHELLO            = 0x02;
    const HEADER_CLIENT_KEY_EXCHANGE    = 0x10;
    const HEADER_CHANGE_CIPHER_SPEC     = 0x14;

    private $connection;
    private $conf;

    public $server;
    public $client;
    private $cipher;
    private $messages = [];

    private $status = false;

    public function __construct($connection,$conf)
    {
        $this->connection = $connection;
        $this->conf = $conf;
    }

    public function rawPackage($raw)
    {
        if($this->getStatus()){
            $this->clientHelloDone($raw);
            $package = $this->serverHandshakeFinished();
            socket_write($this->connection,$package);
            return;
        }
        switch(unpack("C*",substr($raw,0,1))[1]){
            case self::HEADER_CLIENTHELLO:
                $this->clientHello($raw);
                $this->changeCipher();
                if($this->getCipher()==null){
                    socket_write($this->connection,pack("C*",0x15,0x03,0x03,0x00,0x02,0x02,0x28));
                    return;
                }
                $package  = $this->serverHello();
                $package .= $this->certificates();
                $package .= $this->serverKeyExchange();
                $package .= $this->serverHelloDone();
                socket_write($this->connection,$package);
            break;
            case self::HEADER_CLIENT_KEY_EXCHANGE:
                $this->clientKeyExchange($raw);
                $this->server["PreMasterSecret"] = $this->cipher->getPreMasterSecret($this->client['public']);
                $this->server['MasterSecret'] = $this->cipher->getMasterSecret($this->client['random'],$this->server['random'],$this->server['PreMasterSecret']);
                $this->generateEncryptionKeys($this->server['MasterSecret'],$this->client['random'],$this->server['random']);
                $this->status = true;
            break;
        }
    }
    public function getStatus()
    {
        return $this->status;
    }
    public function getCipher()
    {
        return $this->cipher;
    }
    private function clientHello($raw)
    {
        $this->messages[] = $raw;
        $i=0;
        $handshakeHeader = substr($raw,$i,4);$i+=4;
        if(unpack("C",$handshakeHeader)[1]!=0x01) return false;
        $handshake = [];
        $handshake['length'] = hexdec(unpack("H6",$handshakeHeader,1)[1]);
        $handshakeVersion = substr($raw,$i,2);$i+=2;
        $handshake['version'] = $handshakeVersion;
        $handshakeRandom = substr($raw,$i,32);$i+=32;
        $handshake['random'] = $handshakeRandom;
        $handshakeSessionLength = substr($raw,$i,1);$i+=1;
        $handshake['session-length'] = unpack("H*",$handshakeSessionLength)[1];
        $handshakeSession = substr($raw,$i,hexdec($handshake['session-length']));$i+=hexdec($handshake['session-length']);
        $handshake['session'] = unpack("H*",$handshakeSession)[1];
        $handshakeChipherCount = substr($raw,$i,2);$i+=2;
        $handshake['ciphers-count'] = hexdec(unpack("H4",$handshakeChipherCount)[1]);
        $handshakeChiphers = substr($raw,$i,$handshake['ciphers-count']);$i+=$handshake['ciphers-count'];
        $handshake['ciphers'] = $this->parseCipherSuites($handshakeChiphers);
        $handshakeCompression = substr($raw,$i,2);$i+=2;
        $handshake['compression'] = unpack("H*",$handshakeCompression)[1];
        $handshakeExtensionsLength = substr($raw,$i,2);$i+=2;
        $this->client = $handshake;
        if(empty($handshakeExtensionsLength)) return $handshake;
        $handshake['extensions-length'] = hexdec(unpack("H4",$handshakeExtensionsLength)[1]);
        $handshakeExtensions = $handshakeCompression = substr($raw,$i,$handshake['extensions-length']);$i+=$handshake['extensions-length'];
        $handshake['extensions'] = $this->parseHandshakeExtensions($handshakeExtensions);
        $this->client = $handshake;
        return $handshake;
    }

    private function serverHello()
    {
        $package = "";
        $this->server['random'] = openssl_random_pseudo_bytes(32);
        $package .= pack("C*",0x03, 0x03);
        $package .= $this->server['random'];
        $package .= pack("C*",0x00);
        /*$package .= hex2bin($client['session-length']);
        $package .= hex2bin($client['session']);*/
        $package .= $this->cipher->getCipherCode();
        $package .= pack("C*",0x00);
        $extensions = "";
        /*$extensions .= pack("C*",0x00,0x00);
        $extensions .= pack("C*",0x00,0x00);*/
        $extensions .= pack("C*",0xFF,0x01);
        $extensions .= pack("C*",0x00,0x01);
        $extensions .= pack("C*",0x00);
        $package .= TLS::getPackageSize($extensions,2);
        $package .= $extensions;

        $package = TLS::getPackageSize($package,3).$package;
        $package = pack("C*",0x02).$package;

        $this->messages[] = $package;

        $package = TLS::getRecordPackage(0x16,$package);
        return $package;
    }

    private function certificates()
    {
        $package = "";
        /*$package = $this->pem2der(file_get_contents("/usr/local/web/crt/rootCA.crt")).$package;
        $package = $this->getSize($this->pem2der(file_get_contents("/usr/local/web/crt/rootCA.crt")),3).$package;*/
        $cert = file_get_contents($this->conf['tls']['cert']);
        $package = $this->pem2der($cert).$package;
        $package = TLS::getPackageSize($this->pem2der($cert),3).$package;
        $package = TLS::getPackageSize($package,3).$package;
        $package = TLS::getPackageSize($package,3).$package;
        $package = pack("C*",0x0b).$package;
        $this->messages[] = $package;
        $package = TLS::getRecordPackage(0x16,$package);
        unset($cert);
        return $package;
    }

    private function serverKeyExchange()
    {
        $package = "";
        $DHParams = $this->cipher->getDHParams();
        $this->server['dh'] = $this->cipher->getDHResource();
        $sign = $this->cipher->getDHSignature($this->client['random'],$this->server['random'],$DHParams,openssl_pkey_get_private(file_get_contents($this->conf['tls']['priv'])));
        $package = $sign;

        $package = TLS::getPackageSize($package,2).$package;
        $package = $this->cipher->getSignatureAlgoritm().$package;
        $package = $DHParams.$package;
        $package = TLS::getPackageSize($package,3).$package;
        $package = pack("C*",0x0c).$package;

        $this->messages[] = $package;

        $package = TLS::getRecordPackage(0x16,$package);
        return $package;
    }

    private function serverHelloDone()
    {
        $this->messages[] = pack("C*",0x0e,0x00,0x00,0x00);
        return pack("C*",0x16,0x03,0x03,0x00,0x04,0x0e,0x00,0x00,0x00, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01);
    }
    private function serverChangeCipherSpec()
    {
        return pack("C*",0x14, 0x03, 0x03, 0x00, 0x01, 0x01);
    }

    private function clientKeyExchange($raw)
    {
        $this->messages[] = $raw;
        $i=0;
        $handshakeHeader = substr($raw,$i,4);$i+=4;
        if(unpack("C",$handshakeHeader)[1]!=0x10) return false;
        $handshakePublicKeyLenght = substr($raw,$i,$this->cipher->getPubKeyLen());$i+=$this->cipher->getPubKeyLen();
        $this->client['public-length'] = hexdec(unpack("H*",$handshakePublicKeyLenght)[1]);
        $handshakePublicKey = substr($raw,$i,$this->client['public-length']);$i+=$this->client['public-length'];
        $this->client['public'] = $handshakePublicKey;
    }
    private function clientHelloDone($raw)
    {
        $this->messages[] = $this->getCipher()->getDecryptedMessage(null,$raw,"0000000000000000","160303");
    }

    private function generateEncryptionKeys($master_secret, $client_random, $server_random)
    {
        $keys = $this->cipher->generateEncryptionKeys($master_secret, $client_random, $server_random);
        $this->client['mac-key']     = $keys['client']['mac-key'];
        $this->client['write-key']   = $keys['client']['write-key'];
        $this->client['iv-key']      = $keys['client']['iv-key'];
        $this->server['mac-key']     = $keys['server']['mac-key'];
        $this->server['write-key']   = $keys['server']['write-key'];
        $this->server['iv-key']      = $keys['server']['iv-key'];
    }

    private function serverHandshakeFinished()
    {
        $package = "";
        $decrypted = "";
        $a0=$seed = "server finished".hash("sha256",implode("",$this->messages),true);
        $a1 = hash_hmac("sha256",$a0,$this->server['MasterSecret'],true);
        $p1 = hash_hmac("sha256",$a1.$seed,$this->server['MasterSecret'],true);

        $decrypted = substr($p1, 0, 12).$decrypted;
        $decrypted = TLS::getPackageSize($decrypted,3).$decrypted;
        $decrypted = pack("C*",0x14).$decrypted;

        $package = $this->cipher->getEncryptedMessage($this->server['mac-key'],$this->server['write-key'],$decrypted,"0000000000000000","160303");

        $package = TLS::getRecordPackage(0x16,$package);
        return $package;
    }


    private function parseHandshakeExtensions($extensions)
    {
        require_once $this->conf['server-root']."/srv/protocols/tls/extensions.php";
        $ext = new \srv\protocol\tls\Extensions($extensions);
        return $ext->data;
    }

    private function parseCipherSuites($ciphers)
    {
        $list=[];
        $listLenght = strlen($ciphers);
        for($i=0;$i<$listLenght/2;$i++){
            $list[strtoupper(bin2hex(substr($ciphers,$i*2,2)))] = true;
        }
        return $list;
    }

    private function changeCipher()
    {
        $this->server['ciphers'] = json_decode(file_get_contents($this->conf['server-root'].'/srv/protocols/tls/ciphers/manifest.json'),true);
        foreach($this->server['ciphers'] as $key => $value){
            if(isset($this->client['ciphers'][$key])){
                if(!file_exists($this->conf['server-root']."/srv/protocols/tls/ciphers/".$value.".php")) continue;
                require_once $this->conf['server-root']."/srv/protocols/tls/ciphers/".$value.".php";
                $cipher = '\srv\tls\chiper\\'.$value;
                $this->cipher = new $cipher();
                return;
            }
        }
    }
    private function pem2der($pem,$str="CERTIFICATE")
    {
        $begin = $str."-----";
        $end   = "-----END";
        $pem = substr($pem, strpos($pem, $begin)+strlen($begin));
        $pem = substr($pem, 0, strpos($pem, $end));
        $der = base64_decode($pem);
        return $der;
    }
}
