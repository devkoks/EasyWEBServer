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
        slog("INFO","Check shared memory...");
        $this->shm = shm_attach(1,$this->lim);

        if($this->shm == false){
            slog("ERROR","Error allocate \"".$this->lim."\" bytes shared memory");
            exit();
        }
        $st = shm_put_var($this->shm,0,serialize([]));
        if($st == false){
            slog("ERROR","Shared memory is not writeable");
            exit();
        }
        slog("OK","Shared memory is ready");
        slog("INFO","Initialization IPC messages...");
        $this->msg = msg_get_queue(ftok(__FILE__,"s"),0444);
        slog("OK","IPC messages is ready");
    }
    public function __destruct()
    {
        //$this->close();
    }
    public function get($name)
    {
        if(!$this->isset($name)) return null;
        return unserialize(unserialize(shm_get_var($this->shm,0))[$name]);
    }
    public function set($name, $var)
    {
        $mem = unserialize(shm_get_var($this->shm,0));
        $mem[$name] = serialize($var);
        return shm_put_var($this->shm,0,serialize($mem));
    }
    public function isset($name)
    {
        $mem = unserialize(shm_get_var($this->shm,0));
        return isset($mem[$name]);
    }
    public function send($type,$msg)
    {
        return msg_send($this->msg,$type,$msg,true,true,$err);
    }
    public function recv($channel=0)
    {
        msg_receive($this->msg,$channel,$type,$this->blk,$msg,true,MSG_IPC_NOWAIT,$err);
        return $msg;
    }
    public function close()
    {
        //if(get_resource_type($this->shm)!="POSIX shared memory") return;
        shm_detach($this->shm);
        slog("OK","Shared memory closed");
        msg_remove_queue($this->msg);
        slog("OK","IPC messages queue removed");
    }
}
