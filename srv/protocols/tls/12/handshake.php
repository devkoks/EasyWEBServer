<?php
namespace srv\protocol\tls\tls12;

class Handshake extends \TLS
{
    const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = 0xCCA8;
    const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9;
    const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = 0xC02F;
    const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = 0xC030;
    const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = 0xC02B;
    const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = 0xC02C;
    const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = 0xC013;
    const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = 0xC009;
    const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = 0xC014;
    const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          = 0xC00A;
    const TLS_RSA_WITH_AES_128_GCM_SHA256               = 0x009C;
    const TLS_RSA_WITH_AES_256_GCM_SHA384               = 0x009D;
    const TLS_RSA_WITH_AES_128_CBC_SHA                  = 0x002F;
    const TLS_RSA_WITH_AES_256_CBC_SHA                  = 0x0035;
    const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           = 0xC012;
    const TLS_RSA_WITH_3DES_EDE_CBC_SHA                 = 0x000A;

    private $connection;
    private $client;
    private $server;
    private $messages = [];
    private $chiper;

    public function handshake($connection)
    {
        $this->connection = $connection;
        $this->clientHello($connection);
        $this->serverHello($connection);
        $this->clientKeyExchange($connection);
        $this->clientChangeCipherSpec($connection);
        $this->clientHelloDoneHandshake($connection);
        $this->serverHandshakeFinished($connection);
    }
    public function recv($connection)
    {
        $decrypted="";
        socket_recv($connection, $recordHeader, 5, MSG_WAITALL);
        if(unpack("C",$recordHeader)[1]!=0x17) return false;
        $record = [];
        $record['version'] = 0x0303;
        $record['length'] = hexdec(unpack("H4",$recordHeader,3)[1]);
        //var_dump($record['length']);
        $ivLenght = openssl_cipher_iv_length("aes-128-cbc");
        socket_recv($connection, $recordIV, $ivLenght, MSG_WAITALL);

        //$ivLenght

        socket_recv($connection, $recordEncryptedData, $record['length']-$ivLenght, MSG_WAITALL);
        $decrypted = openssl_decrypt($recordEncryptedData,"aes-128-cbc",$this->client['write-key'],OPENSSL_RAW_DATA,$recordIV);
        //var_dump(substr($decrypted,0,$record['length']-52));4
        /*var_dump(substr($decrypted, 0, -35));
        var_dump(bin2hex($decrypted));
                $seq = "0000000000000001";
                $rechd = "170303";
                $datalen = "0004";
                $data = substr($decrypted, 0, 4);
        $mac_key = hash_hmac("sha256", hex2bin($seq.$rechd.$datalen).$data, $this->client['mac-key'], true);
        var_dump(bin2hex($mac_key));*/
        //var_dump(bin2hex(substr($decrypted,$record['length']-52,$record['length'])));
        return $decrypted;
    }
    public function send($connection,$content)
    {
        $package = "";
        $ivLenght = openssl_cipher_iv_length("aes-128-cbc");
        $encryptionIV = openssl_random_pseudo_bytes($ivLenght);
        $seq = "0000000000000001";
        $rechd = "170303";
        $len = unpack("H*",pack("@2N",strlen($content)))[1];
        $datalen = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]);

        $mac_key = hash_hmac("sha1", hex2bin($seq.$rechd).$datalen.$content, $this->server['mac-key'], true);

        $paddingLen = 16-(strlen($content.$mac_key) % 16)-1;

        $encrypt = openssl_encrypt($content.$mac_key.pack("C*",$paddingLen),"aes-128-cbc",$this->server['write-key'], OPENSSL_RAW_DATA, $encryptionIV);

        $package = $encrypt.$package;
        $package = $encryptionIV.$package;
        $len = unpack("H*",pack("@2N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;

        $package = pack("C*",0x17,0x03,0x03).$package;
        socket_write($connection,$package);
    }
    public function clientHello($connection)
    {
        $record = $this->clientHelloRecordHeader($connection);
        $handshake = $this->clientHelloHandshake($connection);
        $this->client = $handshake;
        //require_once "/usr/local/web/srv/protocols/tls/chipers/T";
    }
    public function serverHello($connection)
    {
        $package = $this->serverHelloHandshake($connection,$this->client);
        $package .= $this->serverCertificateHandshake($connection,$this->client);
        $package .= $this->serverKeyExchangeHandshake($connection,$this->client);
        $package .= $this->serverHelloDoneHandshake($connection);
        socket_write($connection,$package);
    }

    private function clientHelloRecordHeader($connection)
    {
        socket_recv($connection, $recordHeader, 5, MSG_WAITALL);
        if(unpack("C",$recordHeader)[1]!=0x16) return false;
        $record = [];
        $record['version'] = 0x0303;
        $record['length'] = hexdec(unpack("H4",$recordHeader,3)[1]);
        return $record;
    }
    private function clientHelloHandshake($connection)
    {
        socket_recv($connection, $handshakeHeader, 4, MSG_WAITALL);
        if(unpack("C",$handshakeHeader)[1]!=0x01) return false;
        $handshake = [];
        $handshake['length'] = hexdec(unpack("H6",$handshakeHeader,1)[1]);
        $this->messages[] = $handshakeHeader;
        socket_recv($connection, $handshakeVersion, 2, MSG_WAITALL);
        $handshake['version'] = 0x0303;
        $this->messages[] = $handshakeVersion;
        socket_recv($connection, $handshakeRandom, 32, MSG_WAITALL);
        $handshake['random'] = $handshakeRandom;
        $this->messages[] = $handshakeRandom;
        socket_recv($connection, $handshakeSessionLength, 1, MSG_WAITALL);
        $handshake['session-length'] = unpack("H*",$handshakeSessionLength)[1];
        $this->messages[] = $handshakeSessionLength;
        socket_recv($connection, $handshakeSession, hexdec($handshake['session-length']), MSG_WAITALL);
        $handshake['session'] = unpack("H*",$handshakeSession)[1];
        $this->messages[] = $handshakeSession;
        socket_recv($connection, $handshakeChipherCount, 2, MSG_WAITALL);
        $handshake['chipher-count'] = hexdec(unpack("H4",$handshakeChipherCount)[1]);
        $this->messages[] = $handshakeChipherCount;
        socket_recv($connection, $handshakeChiphers, $handshake['chipher-count'], MSG_WAITALL);
        $handshake['chiphes'] = unpack("H*",$handshakeChiphers)[1];
        $this->messages[] = $handshakeChiphers;
        socket_recv($connection, $handshakeCompression, 2, MSG_WAITALL);
        $handshake['compression'] = unpack("H*",$handshakeCompression)[1];
        $this->messages[] = $handshakeCompression;
        socket_recv($connection, $handshakeExtensionsLength, 2, MSG_WAITALL);
        $handshake['extensions-length'] = hexdec(unpack("H4",$handshakeExtensionsLength)[1]);
        $this->messages[] = $handshakeExtensionsLength;
        socket_recv($connection, $handshakeExtensions, $handshake['extensions-length'], MSG_WAITALL);
        $handshake['extensions'] = $this->parseHandshakeExtensions($handshakeExtensions);

        $this->messages[] = $handshakeExtensions;

        return $handshake;
    }
    private function parseHandshakeExtensions($extensions)
    {
        require_once "/usr/local/web/srv/protocols/tls/extensions.php";
        $ext = new \srv\protocol\tls\Extensions($extensions);
        //var_dump($ext->data);
        return $ext->data;
    }
    private function serverHelloHandshake($connection,$client)
    {
        $package = "";
        $this->server['random'] = openssl_random_pseudo_bytes(32);
        $package .= pack("C*",0x03, 0x03);
        $package .= $this->server['random'];
        $package .= pack("C*",0x00);
        /*$package .= hex2bin($client['session-length']);
        $package .= hex2bin($client['session']);*/
        $package .= pack("C*",0x00,0x33);
        $package .= pack("C*",0x00);
        $extensions = "";
        /*$extensions .= pack("C*",0x00,0x00);
        $extensions .= pack("C*",0x00,0x00);*/
        $extensions .= pack("C*",0xFF,0x01);
        $extensions .= pack("C*",0x00,0x01);
        $extensions .= pack("C*",0x00);
        $package .= $this->getPackageSize($extensions,2);
        $package .= $extensions;

        $package = $this->getSize($package,3).$package;
        $package = pack("C*",0x02).$package;

        $this->messages[] = $package;

        $package = $this->handshakeRecord($package);
        return $package;
    }
    private function serverCertificateHandshake($connection,$client)
    {
        $package = "";
        /*$package = $this->pem2der(file_get_contents("/usr/local/web/crt/rootCA.crt")).$package;
        $package = $this->getSize($this->pem2der(file_get_contents("/usr/local/web/crt/rootCA.crt")),3).$package;*/
        $package = $this->pem2der(file_get_contents("/etc/letsencrypt/live/8on.ru/cert.pem")).$package;
        $package = $this->getSize($this->pem2der(file_get_contents("/etc/letsencrypt/live/8on.ru/cert.pem")),3).$package;
        $package = $this->getSize($package,3).$package;
        $package = $this->getSize($package,3).$package;
        $package = pack("C*",0x0b).$package;
        $this->messages[] = $package;
        $package = $this->handshakeRecord($package);
        return $package;
    }

    private function serverKeyExchangeHandshake($connection,$client)
    {
        $p = hex2bin('dcf93a0b883972ec0e19989ac5a2ce310e1d37717e8d9571bb7623731866e61ef75a2e27898b057f9891c2e27a639c3f29b60814581cd3b2ca3986d2683705577d45c2e7e52dc81c7a171876e5cea74b1448bfdfaf18828efd2519f14e45e3826634af1949e5b535cc829a483b8a76223e5d490a257f05bdff16f2fb22c583ab829a483b8a76223e5d490a257f05bdff16f2fb22c583ab');
        $g = pack("H*",'02');
        $dh = openssl_pkey_new([
            'private_key_type'=>OPENSSL_KEYTYPE_DH,
            'dh'=>[
                'p'=>$p,
                'g'=>$g
            ]
        ]);
        $this->server['dh'] = $dh;
        $key = openssl_pkey_get_details($dh);
        $package = "";
        $sign="";

        $signSTR = $key['dh']['pub_key'];
        $signSTR = $this->getSize($key['dh']['pub_key'],2).$signSTR;
        $signSTR = $key['dh']['g'].$signSTR;
        $signSTR = $this->getSize($key['dh']['g'],2).$signSTR;
        $signSTR = $key['dh']['p'].$signSTR;
        $signSTR = $this->getSize($key['dh']['p'],2).$signSTR;

        openssl_sign($this->client['random'].$this->server['random'].$signSTR, $sign, openssl_pkey_get_private(file_get_contents("/etc/letsencrypt/live/8on.ru/privkey.pem")),"sha1WithRSAEncryption");
        $package = $sign;
        $package = $this->getSize($package,2).$package;
        $package = pack("C*",0x02,0x01).$package;
        $package = $signSTR.$package;
        $package = $this->getSize($package,3).$package;
        $package = pack("C*",0x0c).$package;

        $this->messages[] = $package;

        $package = $this->handshakeRecord($package);
        return $package;
    }

    private function serverHelloDoneHandshake($connection)
    {
        $this->messages[] = pack("C*",0x0e,0x00,0x00,0x00);
        return pack("C*",0x16,0x03,0x03,0x00,0x04,0x0e,0x00,0x00,0x00, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01);
    }

    private function clientKeyExchange($connection)
    {
        socket_recv($connection, $recordHeader, 5, MSG_WAITALL);
        if(unpack("C",$recordHeader)[1]!=0x16) return false;
        socket_recv($connection, $handshakeHeader, 4, MSG_WAITALL);
        if(unpack("C",$handshakeHeader)[1]!=0x10) return false;

        $this->messages[] = $handshakeHeader;

        socket_recv($connection, $handshakePublicKeyLenght, 2, MSG_WAITALL);
        $this->client['public-length'] = hexdec(unpack("H*",$handshakePublicKeyLenght)[1]);
        $this->messages[] = $handshakePublicKeyLenght;
        socket_recv($connection, $handshakePublicKey, $this->client['public-length'], MSG_WAITALL);
        $this->client['public'] = $handshakePublicKey;
        $this->messages[] = $handshakePublicKey;
        $this->server["PreMasterSecret"] = openssl_dh_compute_key($this->client['public'], $this->server['dh']);
    }
    private function clientChangeCipherSpec($connection)
    {
        socket_recv($connection, $recordHeader, 6, MSG_WAITALL);
    }
    private function clientHelloDoneHandshake($connection)
    {
        $record = [];
        socket_recv($connection, $recordHeader, 5, MSG_WAITALL);
        if(unpack("C",$recordHeader)[1]!=0x16) return false;
        $record['length'] = hexdec(unpack("H4",$recordHeader,3)[1]);

        $ivLenght = openssl_cipher_iv_length("aes-128-cbc");

        socket_recv($connection, $recordIV, $ivLenght, MSG_WAITALL);

        $this->client['iv'] = $recordIV;

        socket_recv($connection, $recordEncryptedData, $record['length']-$ivLenght, MSG_WAITALL);
        $decrypted = "";
        $this->generateMasterSecret();
        $this->generateEncryptionKeys($this->server['MasterSecret'], $this->client['random'], $this->server['random']);
        $decrypted = openssl_decrypt($recordEncryptedData,"aes-128-cbc",$this->client['write-key'],OPENSSL_RAW_DATA,$this->client['iv']);
        $this->messages[] = substr($decrypted, 0, 16);
        $seq = "0000000000000000";
        $rechd = "160303";
        $datalen = "0010";
        $client_mac = hash_hmac("sha1", hex2bin($seq.$rechd.$datalen).substr($decrypted, 0, 16), $this->client['mac-key'], true);
        var_dump($record['length']);
        var_dump(bin2hex($decrypted));
        var_dump(bin2hex($client_mac));
    }

    private function p_hash($algo, $secret, $seed, $size) {
        $output = "";
        $a = $seed;
        while (strlen($output) < $size) {
            $a = hash_hmac($algo, $a, $secret, true);
            $output .= hash_hmac($algo, $a . $seed, $secret, true);
        }
        return substr($output, 0, $size);
    }

    private function generateMasterSecret()
    {
        $this->server['MasterSecret'] = $this->prf_tls12($this->server['PreMasterSecret'], "master secret", $this->client['random'].$this->server['random'], 48);
    }
    private function generateEncryptionKeys($master_secret, $client_random, $server_random) {
        $key_buffer = $this->prf_tls12($master_secret, "key expansion", $server_random.$client_random, 128);
        /*$this->client['mac-key'] = substr($key_buffer, 0, 32);
        $this->server['mac-key'] = substr($key_buffer, 32, 32);
        $this->client['write-key'] = substr($key_buffer, 64, 16);
        $this->server['write-key'] = substr($key_buffer, 80, 16);
        $this->client['iv-key'] = substr($key_buffer, 96, 16);
        $this->server['iv-key'] = substr($key_buffer, 112, 16);*/
        $this->client['mac-key'] = substr($key_buffer, 0, 20);
        $this->server['mac-key'] = substr($key_buffer, 20, 20);
        $this->client['write-key'] = substr($key_buffer, 40, 16);
        $this->server['write-key'] = substr($key_buffer, 56, 16);
        $this->client['iv-key'] = substr($key_buffer, 72, 16);
        $this->server['iv-key'] = substr($key_buffer, 88, 16);
    }
    protected function prf_tls12($secret, $label, $seed, $size = 48) {
        return $this->p_hash("sha256", $secret, $label . $seed, $size);
    }

    private function serverHandshakeFinished($connection)
    {
        $package = "";
        $decrypted = "";
        $a0=$seed = "server finished".hash("sha256",implode("",$this->messages),true);
        $a1 = hash_hmac("sha256",$a0,$this->server['MasterSecret'],true);
        $p1 = hash_hmac("sha256",$a1.$seed,$this->server['MasterSecret'],true);

        $decrypted = substr($p1, 0, 12).$decrypted;
        $decrypted = $this->getSize($decrypted,3).$decrypted;
        $decrypted = pack("C*",0x14).$decrypted;

        $ivLenght = openssl_cipher_iv_length("aes-128-cbc");
        $encryptionIV = openssl_random_pseudo_bytes($ivLenght);

        $seq = "0000000000000000";
        $rechd = "160303";
        $datalen = $this->getSize($decrypted,2);
        $mac_key = hash_hmac("sha1", hex2bin($seq.$rechd).$datalen.$decrypted, $this->server['mac-key'], true);
        $encrypt = openssl_encrypt($decrypted.$mac_key.hex2bin('0b'),"aes-128-cbc",$this->server['write-key'], OPENSSL_RAW_DATA, $encryptionIV);
        $package = $encrypt.$package;
        $package = $encryptionIV.$package;
        $package = $this->handshakeRecord($package,true);
        var_dump(strtoupper(bin2hex($decrypted.$mac_key.hex2bin("0f"))));
        var_dump(strtoupper(bin2hex($encryptionIV)));
        var_dump(strtoupper(bin2hex($this->server['mac-key'])));
        var_dump(strtoupper(bin2hex(hex2bin($seq.$rechd).$datalen.$decrypted)));
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
    private function handshakeRecord($record,$sent=false)
    {
        $package = pack("C*",0x16,0x03,0x03);
        $package .= $this->getSize($record,2);
        $package .= $record;
        if($sent) socket_write($this->connection,$package);
        return $package;
    }
    private function getSize($package,$bytes=2)
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
