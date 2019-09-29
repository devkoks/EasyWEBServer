<?php
namespace srv;

class IPC
{
    private $lim    = 134217728;
    private $shm    = null;
    private $msg    = null;
    private $blk    = 16;


    public function __construct($name=null)
    {
        print "Pre attach".PHP_EOL;
        $this->shm = posix_shm_attach("easywebserver4",128000);
        print "Post attach".PHP_EOL;
        if($this->shm == false)
            throw new \Exception("Error allocate shared memory", 1);
        print "Pre write".PHP_EOL;
        //$this->close();
        //exit();
        $st = posix_shm_write($this->shm,serialize([]));
        if($st == false){
            exit();
        }
        print "Post write".PHP_EOL;
        $this->msg = msg_get_queue(ftok(__FILE__,"s"),0444);
    }
    public function __destruct()
    {
        //$this->close();
    }
    public function get($name)
    {
        if(!$this->isset($name)) return null;
        return unserialize(unserialize(posix_shm_read($this->shm))[$name]);
    }
    public function set($name, $var)
    {
        $mem = unserialize(posix_shm_read($this->shm));
        $mem[$name] = serialize($var);
        posix_shm_write($this->shm,serialize($mem));
    }
    public function isset($name)
    {
        $mem = unserialize(posix_shm_read($this->shm));
        return isset($mem[$name]);
    }
    public function send($type,$msg)
    {
        msg_send($this->msg,$type,$msg,true,true,$err);
    }
    public function recv($channel=0)
    {
        msg_receive($this->msg,$channel,$type,$this->blk,$msg,true,MSG_IPC_NOWAIT,$err);
        return $msg;
    }
    public function close()
    {
        if(get_resource_type($this->shm)!="POSIX shared memory") return;
        posix_shm_close($this->shm);
        msg_remove_queue($this->msg);
    }
}
