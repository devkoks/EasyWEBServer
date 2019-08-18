<?php
namespace srv\tls\chiper;

use srv\protocol\TLS;

class TLS_DHE_RSA_WITH_AES_128_CBC_SHA
{
	const CIPHER_CODE = [0x00,0x33];
	const CIPHER_SIGNATURE_ALGO = [0x02,0x01];

	const DISABLED = true;

	private $private;
	private $p='dcf93a0b883972ec0e19989ac5a2ce310e1d37717e8d9571bb7623731866e61ef75a2e27898b057f9891c2e27a639c3f29b60814581cd3b2ca3986d2683705577d45c2e7e52dc81c7a171876e5cea74b1448bfdfaf18828efd2519f14e45e3826634af1949e5b535cc829a483b8a76223e5d490a257f05bdff16f2fb22c583ab829a483b8a76223e5d490a257f05bdff16f2fb22c583ab';
	private $g='02';
	private $dh;
	private $keys;

	public function getCipherCode()
	{
		return pack('C*',self::CIPHER_CODE[0],self::CIPHER_CODE[1]);
	}
	public function getPubKeyLen()
    {
        return 2;
    }
    public function getDHParams()
    {
        $this->dh = openssl_pkey_new([
            'private_key_type'=>OPENSSL_KEYTYPE_DH,
            'dh'=>[
                'p'=>hex2bin($this->p),
                'g'=>hex2bin($this->g)
            ]
        ]);
        $key = openssl_pkey_get_details($this->dh);

        $DHParams = $key['dh']['pub_key'];
        $DHParams = TLS::getPackageSize($key['dh']['pub_key'],2).$DHParams;
        $DHParams = $key['dh']['g'].$DHParams;
        $DHParams = TLS::getPackageSize($key['dh']['g'],2).$DHParams;
        $DHParams = $key['dh']['p'].$DHParams;
        $DHParams = TLS::getPackageSize($key['dh']['p'],2).$DHParams;
        return $DHParams;
    }
    public function getDHSignature($clientRandom,$serverRandom,$DHParams,$privateKey)
    {
        $signature = "";
        openssl_sign($clientRandom.$serverRandom.$DHParams, $signature, $privateKey,"sha1WithRSAEncryption");
        return $signature;
    }
	public function getSignatureAlgoritm()
	{
		return pack('C*',self::CIPHER_SIGNATURE_ALGO[0],self::CIPHER_SIGNATURE_ALGO[1]);
	}
    public function getDHResource()
    {
        return $this->dh;
    }
    public function generateEncryptionKeys($master_secret, $client_random, $server_random) {
        $key_buffer = $this->prf_tls12($master_secret, "key expansion", $server_random.$client_random, 104);
        $keys = ['client'=>[],'server'=>[]];
        $keys['client']['mac-key'] = substr($key_buffer, 0, 20);
        $keys['server']['mac-key'] = substr($key_buffer, 20, 20);
        $keys['client']['write-key'] = substr($key_buffer, 40, 16);
        $keys['server']['write-key'] = substr($key_buffer, 56, 16);
        $keys['client']['iv-key'] = substr($key_buffer, 72, 16);
        $keys['server']['iv-key'] = substr($key_buffer, 88, 16);
		$this->keys = $keys;
        return $keys;
    }
    protected function prf_tls12($secret, $label, $seed, $size = 48) {
        return $this->p_hash("sha256", $secret, $label . $seed, $size);
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

	public function getPreMasterSecret($public)
	{
		return openssl_dh_compute_key($public, $this->dh);
	}
    public function getMasterSecret($clientRandom,$serverRandom,$preMasterSecret)
    {
        return $this->prf_tls12($preMasterSecret, "master secret", $clientRandom.$serverRandom, 48);
    }
    public function getEncryptedMessage($serverMac,$serverWriteKey,$message,$seq="0000000000000000",$rechd="170303")
    {
		if($serverMac==null) $serverMac = $this->keys['server']['mac-key'];
		if($serverWriteKey==null) $serverWriteKey = $this->keys['server']['write-key'];
        $ivLenght = openssl_cipher_iv_length("aes-128-cbc");
        $encryptionIV = openssl_random_pseudo_bytes($ivLenght);
        $datalen = TLS::getPackageSize($message,2);
        $mac_key = hash_hmac("sha1", hex2bin($seq.$rechd).$datalen.$message, $serverMac, true);
        $paddingLen = 16-(strlen($message.$mac_key) % 16)-1;
		if($paddingLen==0)
			$paddingLen = 16;
        $encrypt = openssl_encrypt($message.$mac_key.pack('C*',$paddingLen),"aes-128-cbc",$serverWriteKey, OPENSSL_RAW_DATA, $encryptionIV);
        return $encryptionIV.$encrypt;
    }
    public function getDecryptedMessage($clientWriteKey,$message,$seq,$rechd)
    {
		$clientWriteKey = $this->keys['client']['write-key'];
        $ivLenght = openssl_cipher_iv_length("aes-128-cbc");
        $recordIV = substr($message,0,$ivLenght);
        $recordEncryptedData = substr($message,$ivLenght,strlen($message));
        $decrypted = openssl_decrypt($recordEncryptedData,"aes-128-cbc",$clientWriteKey,OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING,$recordIV);
        $padding = substr($decrypted,-1);
        $paddingLen = hexdec(bin2hex($padding));
        $decrypted = substr($decrypted,0,strlen($decrypted)-$paddingLen-1);//remove paddings
        $decrypted = substr($decrypted,0,strlen($decrypted)-20);
        return $decrypted;
    }
}
