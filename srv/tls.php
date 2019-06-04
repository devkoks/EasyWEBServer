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

    public function handshake()
    {

    }
    public function clientHello($connection)
    {
        $record = $this->clientHelloRecordHeader($connection);
        $handshake = $this->clientHelloHandshake($connection);
        $this->serverHelloHandshake($connection,$handshake);
        $this->serverCertificateHandshake($connection,$handshake);
        $this->serverKeyExchangeHandshake($connection,$handshake);
        $this->serverHelloDoneHandshake($connection);
        var_dump($handshake);
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
        socket_recv($connection, $handshakeVersion, 2, MSG_WAITALL);
        $handshake['version'] = $this->getProtocol(hexdec(unpack("H4",$handshakeVersion)[1]));
        socket_recv($connection, $handshakeRandom, 32, MSG_WAITALL);
        $handshake['random'] = unpack("H*",$handshakeRandom)[1];
        socket_recv($connection, $handshakeSessionLength, 1, MSG_WAITALL);
        $handshake['session-length'] = unpack("H*",$handshakeSessionLength)[1];
        socket_recv($connection, $handshakeSession, hexdec($handshake['session-length']), MSG_WAITALL);
        $handshake['session'] = unpack("H*",$handshakeSession)[1];
        socket_recv($connection, $handshakeChipherCount, 2, MSG_WAITALL);
        $handshake['chipher-count'] = hexdec(unpack("H4",$handshakeChipherCount)[1]);
        socket_recv($connection, $handshakeChiphers, $handshake['chipher-count'], MSG_WAITALL);
        $handshake['chiphes'] = unpack("H*",$handshakeChiphers)[1];
        socket_recv($connection, $handshakeCompression, 2, MSG_WAITALL);
        $handshake['compression'] = unpack("H*",$handshakeCompression)[1];
        socket_recv($connection, $handshakeExtensionsLength, 2, MSG_WAITALL);
        $handshake['extensions-length'] = hexdec(unpack("H4",$handshakeExtensionsLength)[1]);
        socket_recv($connection, $handshakeExtensions, $handshake['extensions-length'], MSG_WAITALL);
        $handshake['extensions'] = unpack("H*",$handshakeExtensions)[1];

        return $handshake;
    }
    private function parseHandshakeExtensions($extensions)
    {

    }
    private function serverHelloHandshake($connection,$client)
    {
        $package = "";

        $package .= pack("C*",0x03, 0x03);
        $package .= openssl_random_pseudo_bytes(32);
        $package .= hex2bin($client['session-length']);
        $package .= hex2bin($client['session']);
        $package .= pack("C*",0xC0,0x2F);
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

        $len = unpack("H*",pack("@2N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        $package = pack("C*",0x03, 0x03).$package;
        $package = pack("C*",0x16).$package;

        socket_write($connection,$package);
    }
    private function serverCertificateHandshake($connection,$client)
    {
        $package = $this->pem2der(file_get_contents("/usr/local/web/crt/web.pem"));

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
        $len = unpack("H*",pack("@3N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-6].$len[strlen($len)-5].
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        $package = pack("C*",0x0b).$package;
        $len = unpack("H*",pack("@2N",strlen($package)))[1];
        $package = hex2bin(
            $len[strlen($len)-4].$len[strlen($len)-3].
            $len[strlen($len)-2].$len[strlen($len)-1]
            ).$package;
        $package = pack("C*",0x03,0x03).$package;
        $package = pack("C*",0x16).$package;
        socket_write($connection,$package);
    }
    private function serverKeyExchangeHandshake($connection,$client)
    {
        /*$dh = openssl_pkey_new([
            "dh"=>[
                "p"=>"",
                "g"=>hex2bin('02')
            ]
        ]);
        var_dump($dh);*/
        socket_write($connection,hex2bin("160303012c0c00012803001d209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615040101000402b661f7c191ee59be45376639bdc3d4bb81e115ca73c8348b525b0d2338aa144667ed9431021412cd9b844cba29934aaacce873414ec11cb02e272d0ad81f767d33076721f13bf36020cf0b1fd0ecb078de1128beba0949ebece1a1f96e209dc36e4fffd36b673a7ddc1597ad4408e485c4adb2c873841249372523809e4312d0c7b3522ef983cac1e03935ff13a8e96ba681a62e40d3e70a7ff35866d3d9993f9e26a634c81b4e71380fcdd6f4e835f75a6409c7dc2c07410e6f87858c7b94c01c2e32f291769eacca71643b8b98a963df0a329bea4ed6397e8cd01a110ab361ac5bad1ccd840a6c8a6eaa001a9d7d87dc3318643571226c4dd2c2ac41fb"));
    }
    private function serverHelloDoneHandshake($connection)
    {
        socket_write($connection,pack("C*",0x16,0x03,0x03,0x00,0x04,0x0e,0x00,0x00,0x00));
    }

    private function pem2der($pem)
    {
        $begin = "CERTIFICATE-----";
       $end   = "-----END";
       $pem = substr($pem, strpos($pem, $begin)+strlen($begin));
       $pem = substr($pem, 0, strpos($pem, $end));
       $der = base64_decode($pem);
       return $der;
    }
}
