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
        shm_put_var($this->shm,0,[['def']]);
    }
    public function __destruct()
    {
        $this->close();
    }
    public function get($name)
    {
        if(!$this->isset($this->key($name))) return null;
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
    public function close()
    {
        if(get_resource_type($this->shm)!="sysvshm") return;
        shm_remove($this->shm);
        shm_detach($this->shm);
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
