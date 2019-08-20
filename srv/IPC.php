<?php
namespace srv;

class IPC
{
    private $lim    = 134217728;
    private $shm    = null;


    public function __construct($ftok=null)
    {
        if($ftok == null)
            $ftok = ftok(__FILE__,"t");
        $this->shm = shm_attach($ftok,$this->lim);
    }
    public function __destruct()
    {
        $this->close();
    }
    public function get(int $id)
    {
        if(!$this->isset($id)) return null;
        return shm_get_var($this->shm,$id);
    }
    public function set(int $id, $var)
    {
        shm_put_var($this->shm,$id,$var);
    }
    public function isset(int $id)
    {
        return shm_has_var($this->shm,$id);
    }
    public function close()
    {
        if(get_resource_type($this->shm)!="sysvshm") return;
        shm_remove($this->shm);
        shm_detach($this->shm);
    }
}
