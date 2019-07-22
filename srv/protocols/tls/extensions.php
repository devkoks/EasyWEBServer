<?php
namespace srv\protocol\tls;
class Extensions
{
    private $buffer;
    public $data;
    private $extTypes = [
        "0000"=>"ServerName",
        "0005"=>"StatusRequest",
        "000A"=>"SupporedGroups",
        "000B"=>"EcPointFormats",
        "000D"=>"SignatureAlgoritms",
        "0010"=>"ALPN",
        "0015"=>"Padding",
        "0017"=>"ExtendedMasterSecret",
        "0023"=>"SessionTicket",
        "0033"=>"KeyShare",
        "001C"=>"RecordSizeLimit",
        "002B"=>"SupporedVersions",
        "002D"=>"PskKeyExchangeModes",
        "FF01"=>"RenegotiationInfo"
    ];
    private $supporedGroups = [
        "001D"=>"x25519",
        "0017"=>"secp256r1",
        "0018"=>"secp384r1",
        "0019"=>"secp521r1",
        "0100"=>"ffdhe2048",
        "0101"=>"ffdhe3072"
    ];
    private $supporedVersions = [
        "0301"=>"TLS1.0",
        "0302"=>"TLS1.1",
        "0303"=>"TLS1.2",
        "0304"=>"TLS1.3",
    ];
    private $signatureAlgoritms = [
        "0403"=>"ecdsa_secp256r1_sha256",
        "0503"=>"ecdsa_secp384r1_sha384",
        "0603"=>"ecdsa_secp521r1_sha512",
        "0804"=>"rsa_pss_rsae_sha256",
        "0805"=>"rsa_pss_rsae_sha384",
        "0806"=>"rsa_pss_rsae_sha512",
        "0401"=>"rsa_pkcs1_sha256",
        "0501"=>"rsa_pkcs1_sha384",
        "0601"=>"rsa_pkcs1_sha512",
        "0203"=>"ecdsa_sha1",
        "0201"=>"rsa_pkcs1_sha1"
    ];
    public function __construct($raw)
    {
        $extensions = $this->explode($raw);
        foreach($extensions as $extension){
            if(!isset($this->extTypes[strtoupper(unpack("H4",$extension['type'])[1])])) continue;
            $func = 'get'.$this->extTypes[strtoupper(unpack("H4",$extension['type'])[1])];
            if(method_exists($this,$func))
                $this->data[$this->extTypes[strtoupper(unpack("H4",$extension['type'])[1])]] = $this->$func($extension['ext']);
        }
    }
    private function getServerName($ext)
    {
        $this->setBuffer($ext);
        $listLenght = hexdec(unpack("H4",$this->getBuffer(2))[1]);
        $type = $this->getBuffer(1);
        $nameLenght = hexdec(unpack("H4",$this->getBuffer(2))[1]);
        $name = $this->getBuffer($nameLenght);
        return [
            "type"=>"hostName",
            "name"=>$name
        ];
    }
    private function getStatusRequest($ext)
    {

    }
    private function getSupporedGroups($ext)
    {
        $this->setBuffer($ext);
        $list = [];
        $listLenght = hexdec(unpack("H4",$this->getBuffer(2))[1]);
        for($i=0;$i<$listLenght/2;$i++){
            $code = strtoupper(bin2hex($this->getBuffer(2)));
            $name = 'Undefined:'.$code;
            if(isset($this->supporedGroups[$code]))
                $name = $this->supporedGroups[$code];
            $list[] = $name;
        }

        return $list;
    }
    private function getEcPointFormats($ext)
    {

    }
    private function getSignatureAlgoritms($ext)
    {
        $this->setBuffer($ext);
        $list = [];
        $listLenght = hexdec(unpack("H4",$this->getBuffer(2))[1]);
        for($i=0;$i<$listLenght/2;$i++){
            $code = strtoupper(bin2hex($this->getBuffer(2)));
            $name = 'Undefined:'.$code;
            if(isset($this->signatureAlgoritms[$code]))
                $name = $this->signatureAlgoritms[$code];
            $list[] = $name;
        }

        return $list;
    }
    private function getALPN($ext)
    {

    }
    private function getExtendedMasterSecret($ext)
    {

    }
    private function getSessionTicket($ext)
    {

    }
    private function getKeyShare($ext)
    {

    }
    private function getSupporedVersions($ext)
    {
        $this->setBuffer($ext);
        $list = [];
        $listLenght = hexdec(unpack("H2",$this->getBuffer(1))[1]);
        for($i=0;$i<$listLenght/2;$i++){
            $code = strtoupper(bin2hex($this->getBuffer(2)));
            $name = 'Undefined:'.$code;
            if(isset($this->supporedVersions[$code]))
                $name = $this->supporedVersions[$code];
            $list[] = $name;
        }
        return $list;
    }
    private function getPskKeyExchangeModes($ext)
    {

    }
    private function getRenegotiationInfo($ext)
    {

    }
    private function getRecordSizeLimit($ext)
    {
        return hexdec(bin2hex($ext));
    }
    private function getBuffer($bytes)
    {
        $data = substr($this->buffer,0,$bytes);
        $this->buffer = substr($this->buffer,$bytes,strlen($this->buffer));
        return $data;
    }
    private function setBuffer($raw)
    {
        $this->buffer = $raw;
    }
    private function explode($data)
    {
        $extensions = [];
        while(strlen($data)!=0){
            $type = substr($data,0,2);
            $data = substr($data,2);
            $len = hexdec(unpack("H4",substr($data,0,2))[1]);
            $data = substr($data,2);
            $ext = substr($data,0,$len);
            $data = substr($data,$len);
            $extensions[] = ['type'=>$type,'length'=>$len,'ext'=>$ext];
        }
        return $extensions;
    }
}
