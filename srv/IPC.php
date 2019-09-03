<?php
namespace srv;

class IPC
{
    private $lim    = 134217728;
    private $shm    = null;
    private $msg    = null;
    private $blk    = 8;


    public function __construct($ftok=null)
    {
        if($ftok == null)
            $ftok = ftok(__FILE__,"t");
        $this->shm = shm_attach($ftok,$this->lim);
        shm_put_var($this->shm,0,[['def']]);
        $this->msg = msg_get_queue(1,0444);
    }
    public function __destruct()
    {
        $this->close();
    }
    public function get($name)
    {
        if(!$this->isset($name)) return null;
        return shm_get_var($this->shm,$this->key($name));
    }
    public function set($name, $var)
    {
        shm_put_var($this->shm,$this->key($name),$var);
    }
    public function isset($name)
    {
        return shm_has_var($this->shm,$this->key($name));
    }
    public function send($type,$msg)
    {
        msg_send($this->msg,$type,$msg);
    }
    public function recv()
    {
        $state = true;
        $msg = "";
        while($state){
            $state = msg_receive($this->msg,0,$type,$this->blk,$message,true,MSG_IPC_NOWAIT,$err);
            $msg .= $message;
        }
        return $msg;
    }
    public function close()
    {
        if(get_resource_type($this->shm)!="sysvshm") return;
        shm_remove($this->shm);
        shm_detach($this->shm);
        msg_remove_queue($this->msg);
    }
    private function key($name)
    {
        $names = shm_get_var($this->shm,0);
        $key = array_search($name,$names);
        if($key === false){
            $names[] = $name;
            shm_put_var($this->shm,0,$names);
        }

        return array_search($name,$names);
    }
}
