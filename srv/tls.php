<?php
class tls
{

    const PROTOCOL_SSLv3 = 0x0300;
    const PROTOCOL_TLS10 = 0x0301;
    const PROTOCOL_TLS11 = 0x0302;
    const PROTOCOL_TLS12 = 0x0303;

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

    private $protocol_version = 0;
    private $chipher_suite = 0;
    private $client;
    private $server;
    private $messages = [];

    public function getProtocol($byte=null)
    {
        if($byte==null) return $this->protocol_version;
        switch($byte){
            case self::PROTOCOL_SSLv3:
                return self::PROTOCOL_SSLv3;
            case self::PROTOCOL_TLS10:
                return self::PROTOCOL_TLS10;
            case self::PROTOCOL_TLS11:
                return self::PROTOCOL_TLS11;
            case self::PROTOCOL_TLS12:
                return self::PROTOCOL_TLS12;
        }
    }
    public function setProtocol($protocol)
    {
        $this->protocol_version = $protocol;
    }

    public function handshake($connection)
    {
        $this->clientHello($connection);
        $this->serverHello($connection);
        $this->clientKeyExchange($connection);
        $this->clientChangeCipherSpec($connection);
        $this->clientHelloDoneHandshake($connection);
        $this->serverHandshakeFinished($connection);
    }
    public function clientHello($connection)
    {
        $record = $this->clientHelloRecordHeader($connection);
        $handshake = $this->clientHelloHandshake($connection);
        $this->client = $handshake;
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
        $record['version'] = $this->getProtocol(hexdec(unpack("H4",$recordHeader,1)[1]));
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
        $handshake['version'] = $this->getProtocol(hexdec(unpack("H4",$handshakeVersion)[1]));
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
        $handshake['extensions'] = unpack("H*",$handshakeExtensions)[1];
        $this->messages[] = $handshakeExtensions;

        return $handshake;
    }
    private function parseHandshakeExtensions($extensions)
    {

    }
    private function serverHelloHandshake($connection,$client)
    {
        $package = "";
        $this->server['random'] = openssl_random_pseudo_bytes(32);
        $package .= pack("C*",0x03, 0x03);
        $package .= $this->server['random'];
        $package .= hex2bin($client['session-length']);
        $package .= hex2bin($client['session']);
        $package .= pack("C*",0x00,0x67);
        $package .= pack("C*",0x00);
        $package .= pack("C*",0x00,0x05);
        $package .= pack("C*",0xFF,0x01);
        $package .= pack("C*",0x00,0x01);
        $package .= pack("C*",0x00);


        $len = unpack("H*",pack("@3N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-6].$len[strlen($len)-5].
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        $package = pack("C*",0x02).$package;

        $this->messages[] = $package;

        $len = unpack("H*",pack("@2N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        $package = pack("C*",0x03, 0x03).$package;
        $package = pack("C*",0x16).$package;

        return $package;
    }
    private function serverCertificateHandshake($connection,$client)
    {
        $package = "";

        $package = $this->pem2der(file_get_contents("/usr/local/web/crt/rootCA.crt")).$package;

        $len = unpack("H*",pack("@3N",strlen($this->pem2der(file_get_contents("/usr/local/web/crt/rootCA.crt")))))[1];
        $package = hex2bin(
            $len[strlen($len)-6].$len[strlen($len)-5].
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;


        $package = $this->pem2der(file_get_contents("/usr/local/web/crt/web.blue-creature.com.crt")).$package;

        $len = unpack("H*",pack("@3N",strlen($this->pem2der(file_get_contents("/usr/local/web/crt/web.blue-creature.com.crt")))))[1];
        $package = hex2bin(
            $len[strlen($len)-6].$len[strlen($len)-5].
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        $len = unpack("H*",pack("@3N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-6].$len[strlen($len)-5].
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        $len = unpack("H*",pack("@3N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-6].$len[strlen($len)-5].
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        $package = pack("C*",0x0b).$package;
        $this->messages[] = $package;
        $len = unpack("H*",pack("@2N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        $package = pack("C*",0x03,0x03).$package;
        $package = pack("C*",0x16).$package;
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
        $len = unpack("H*",pack("@2N",strlen($key['dh']['pub_key'])))[1];
        $signSTR = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$signSTR;

        $signSTR = $key['dh']['g'].$signSTR;

        $len = unpack("H*",pack("@2N",strlen($key['dh']['g'])))[1];
        $signSTR = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$signSTR;

        $signSTR = $key['dh']['p'].$signSTR;

        $len = unpack("H*",pack("@2N",strlen($key['dh']['p'])))[1];
        $signSTR = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$signSTR;


        openssl_sign($this->client['random'].$this->server['random'].$signSTR, $sign, openssl_pkey_get_private(file_get_contents("/usr/local/web/crt/web.blue-creature.com.key")),"sha256WithRSAEncryption");
        $package = $sign;

        $len = unpack("H*",pack("@2N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;


        $package = pack("C*",0x04,0x01).$package;

        $package = $signSTR.$package;

        $len = unpack("H*",pack("@3N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-6].$len[strlen($len)-5].
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;

        $package = pack("C*",0x0c).$package;

        $this->messages[] = $package;

        $len = unpack("H*",pack("@2N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        //$package = hex2bin("160303").$package;
        $package = pack("C*",0x16,0x03,0x03).$package;
        return $package;
    }

    private function serverHelloDoneHandshake($connection)
    {
        $this->messages[] = pack("C*",0x16,0x03,0x03,0x00,0x04,0x0e,0x00,0x00,0x00);
        return pack("C*",0x16,0x03,0x03,0x00,0x04,0x0e,0x00,0x00,0x00);
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
        if(unpack("C",$recordHeader)[1]!=0x16) return false;
        $this->messages[] = pack("C",0x01);
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
        $this->messages[] = $recordIV;

        socket_recv($connection, $recordEncryptedData, $record['length']-$ivLenght, MSG_WAITALL);
        $this->messages[] = $recordEncryptedData;

        //var_dump(bin2hex($recordEncryptedData));
        $decrypted = "";
        $this->generateMasterSecret();
        $this->generateEncryptionKeys($this->server['MasterSecret'], $this->client['random'], $this->server['random']);
        //var_dump(bin2hex(openssl_decrypt($recordEncryptedData,"aes-128-cbc",$this->client['write-key'],OPENSSL_RAW_DATA,$this->client['iv'])));
        //var_dump($decrypted);
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
        // TLS_RSA_WITH_RC4_128_SHA has 20byte mac + 16byte key means 72 bytes of data is needed
        $key_buffer = $this->prf_tls12($master_secret, "key expansion", $server_random.$client_random, 96);
        $this->client['mac-key'] = substr($key_buffer, 0, 32);
        $this->server['mac-key'] = substr($key_buffer, 32, 32);
        $this->client['write-key'] = substr($key_buffer, 64, 16);
        $this->server['write-key'] = substr($key_buffer, 80, 16);
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
        $p1 = hash_hmac("sha256",$a1,$this->server['MasterSecret'].$seed,true);

        $decrypted = substr($p1, 0, 12).$decrypted;
        var_dump(bin2hex($decrypted));

        $len = unpack("H*",pack("@3N",strlen($decrypted)))[1];
        $decrypted = hex2bin(
            $len[strlen($len)-6].$len[strlen($len)-5].
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$decrypted;

        $decrypted = pack("C*",0x14).$decrypted;

        $ivLenght = openssl_cipher_iv_length("aes-128-cbc");
        $encryptionIV = openssl_random_pseudo_bytes($ivLenght);
        $encrypt = openssl_encrypt($decrypted,"aes-128-cbc",$this->server['write-key'],OPENSSL_RAW_DATA,$encryptionIV);

        $package = $encrypt.$package;
        $package = $encryptionIV.$package;
        $len = unpack("H*",pack("@2N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        $package = pack("C*",0x16,0x03,0x03).$package;
        var_dump(bin2hex($package));
        socket_write($connection,$package);
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
