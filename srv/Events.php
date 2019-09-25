<?php
namespace srv;
class Events
{
    private $events = [];

    public function __construct()
    {
        $_SERVER['__IPC']->set('__EVENTS__',$this->events);
    }

    public function add($name, $event, $thread=false)
    {
        $this->events = $_SERVER['__IPC']->get('__EVENTS__',$this->events);
        $this->events[$name] = [
            'execute'=>$event,
            'thread'=>$thread,
            'type'=>0,
            'timer'=>0,
            'last'=>0
        ];
        $_SERVER['__IPC']->set('__EVENTS__',$this->events);
        return true;
    }

    public function addTimer($name,$time,$isPeriodic=true)
    {
        $this->events = $_SERVER['__IPC']->get('__EVENTS__',$this->events);
        $this->events[$name]['type']  = ($isPeriodic)?0:1;
        $this->events[$name]['timer'] = $time;
        $_SERVER['__IPC']->set('__EVENTS__',$this->events);
        return true;
    }

    public function get($name)
    {
        $this->events = $_SERVER['__IPC']->get('__EVENTS__',$this->events);
        if(!isset($this->events[$name]))
            return null;
        return $this->events[$name];
    }

    public function remove($name)
    {
        $_SERVER['__IPC']->get('__EVENTS__',$this->events);
        unset($this->events[$name]);
        $_SERVER['__IPC']->set('__EVENTS__',$this->events);
        return true;
    }

    public function execute()
    {
        $pid = pcntl_fork();
        if($pid != 0) return;
        $this->events = $_SERVER['__IPC']->get('__EVENTS__',$this->events);
        foreach($this->events as $name => $event){
            $execute = $event['execute'];
            if($event['thread'])
                $pid = pcntl_fork();
            if($pid != 0) return;
            if($event['type']==0&&$event['timer']==0)
                $execute();
            if($event['type']==0&&$event['timer']>0&&(time()-$event['last']>$event['timer']))
                $execute();
            if($event['type']==1&&(time()>=$event['timer']))
                $execute();
            $this->events = $_SERVER['__IPC']->get('__EVENTS__',$this->events);
            $this->events[$name]['last'] = time();
            $_SERVER['__IPC']->set('__EVENTS__',$this->events);
            if($event['thread']) exit();
        }
        exit();
    }
}
