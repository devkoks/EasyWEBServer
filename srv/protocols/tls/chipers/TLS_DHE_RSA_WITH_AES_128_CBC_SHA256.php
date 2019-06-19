<?php
namespace srv\tls\chiper;

class TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 extends \TLS
{
	const CHIPER_CODE = [0x00,0x67];

	private $private;
	private $p='dcf93a0b883972ec0e19989ac5a2ce310e1d37717e8d9571bb7623731866e61ef75a2e27898b057f9891c2e27a639c3f29b60814581cd3b2ca3986d2683705577d45c2e7e52dc81c7a171876e5cea74b1448bfdfaf18828efd2519f14e45e3826634af1949e5b535cc829a483b8a76223e5d490a257f05bdff16f2fb22c583ab829a483b8a76223e5d490a257f05bdff16f2fb22c583ab';
	private $g='02';
	private $dh;


	public function serverKeyExchange($private,$clientRandom,$serverRandom)
	{
        $dh = openssl_pkey_new([
            'private_key_type'=>OPENSSL_KEYTYPE_DH,
            'dh'=>[
                'p'=>hex2bin($this->p),
                'g'=>pack("H*",$this->g)
            ]
        ]);
        $this->dh = $dh;
		$this->private = $private;
        $key = openssl_pkey_get_details($this->dh);
        $package = "";
        $sign="";

        $signSTR = $key['dh']['pub_key'];
        $signSTR = $this->getPackageSize($key['dh']['pub_key'],2).$signSTR;
        $signSTR = $key['dh']['g'].$signSTR;
        $signSTR = $this->getPackageSize($key['dh']['g'],2).$signSTR;
        $signSTR = $key['dh']['p'].$signSTR;
        $signSTR = $this->getPackageSize($key['dh']['p'],2).$signSTR;

        openssl_sign($clientRandom.$serverRandom.$signSTR, $sign, openssl_pkey_get_private($this->private),"sha256WithRSAEncryption");
        $package = $sign;
        $package = $this->getPackageSize($package,2).$package;
        $package = pack("C*",0x04,0x01).$package;
        $package = $signSTR.$package;
        $package = $this->getPackageSize($package,3).$package;
        $package = pack("C*",0x0c).$package;

        $this->messages[] = $package;

        $package = $this->getRecordPackage(0x16,$package);
        return $package;
	}

	public function getPreMasterSecret($public)
	{
		return openssl_dh_compute_key($public, $this->dh);
	}
}
