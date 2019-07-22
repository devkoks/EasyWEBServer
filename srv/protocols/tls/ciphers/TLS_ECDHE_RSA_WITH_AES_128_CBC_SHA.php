<?php
namespace srv\tls\chiper;

use srv\protocol\TLS;

class TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
{
    const CIPHER_CODE = [0xC0,0x13];
    const CIPHER_SIGNATURE_ALGO = [0x02,0x01];

    //const DISABLED = true;

	private $private;
    private $dh;
    private $keys;

    public function getCipherCode()
	{
		return pack('C*',self::CIPHER_CODE[0],self::CIPHER_CODE[1]);
	}
    public function getPubKeyLen()
    {
        return 1;
    }
    public function getDHParams()
    {
        $DHParams = "";
        $this->dh = openssl_pkey_new([
            'private_key_type'=>OPENSSL_KEYTYPE_EC,
			'curve_name'=>'secp384r1'
        ]);
        $key = openssl_pkey_get_details($this->dh);
        $publicKey = pack('C*',0x04).$key['ec']['x'].$key['ec']['y'];

        $DHParams .= pack('C*',0x03,0x00,0x18);
        $DHParams .= TLS::getPackageSize($publicKey,1);
        $DHParams .= $publicKey;
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
        return openssl_ecdh_compute_key($public,$this->dh);
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
        if($paddingLen==0){
			$message .= pack("C",0x00);
			$datalen = TLS::getPackageSize($message,2);
	        $mac_key = hash_hmac("sha1", hex2bin($seq.$rechd).$datalen.$message, $serverMac, true);
			$paddingLen = 16-(strlen($message.$mac_key) % 16)-1;
		}
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
        $paddingLen = dechex(bin2hex($padding));
        for($i=0;$i<$paddingLen;$i++) $decrypted .= $padding;
        $decrypted = substr($decrypted,0,strlen($decrypted)-$paddingLen-1);
        $decrypted = substr($decrypted,0,strlen($decrypted)-20);
        return $decrypted;
    }
}
