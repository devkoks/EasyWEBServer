<?php
namespace srv;
class Events
{
    private $events = [];

    public function __construct()
    {
        if(!$_SERVER['__IPC']->isset('__EVENTS__'))
            $_SERVER['__IPC']->set('__EVENTS__',[]);
    }

    public function add($name, $path, $start=[])
    {
        $thread = true;
        $events = $_SERVER['__IPC']->get('__EVENTS__');
        $events[$name] = [
            'name'=>$name,
            'execute'=>[
                'path'=>$path,
                'object'=>$start['object'],
                'method'=>$start['method'],
                'params'=>$start['params']
            ],
            'thread'=>$thread,
            'type'=>0,
            'timer'=>0,
            'last'=>0
        ];
        $_SERVER['__IPC']->set('__EVENTS__',$events);
        return true;
    }

    public function addTimer($name,$time,$isPeriodic=true)
    {
        $events = $_SERVER['__IPC']->get('__EVENTS__');
        $events[$name]['type']  = ($isPeriodic)?1:0;
        $events[$name]['timer'] = $time;
        if(!$isPeriodic and $time<time())
            $events[$name]['timer']=$time+time();

        if($isPeriodic)
            $events[$name]['last'] = time();
        $_SERVER['__IPC']->set('__EVENTS__',$events);
        return true;
    }

    public function get($name)
    {
        $events = $_SERVER['__IPC']->get('__EVENTS__');
        if(!isset($events[$name]))
            return null;
        return $events[$name];
    }

    public function remove($name)
    {
        $events = $_SERVER['__IPC']->get('__EVENTS__');
        unset($events[$name]);
        $_SERVER['__IPC']->set('__EVENTS__',$events);
        return true;
    }

    public function execute()
    {
        $events = $_SERVER['__IPC']->get('__EVENTS__');
        foreach($events as $name => $event){
            $executed = false;
            if($event['type']==1&&(time()-$event['last']>=$event['timer']))
                $executed = $this->run($event);
            if($event['type']==0&&(time()>=$event['timer']))
                $executed = $this->run($event);
            if($executed)
                $events[$name]['last'] = time();
        }
        $_SERVER['__IPC']->set('__EVENTS__',$events);
    }

    private function run($event)
    {
        if($event['thread']) $pid = pcntl_fork();
        if($pid != 0) return true;
        if(!file_exists($event['execute']['path'])){
            slog("ERROR","Event \"".$event['name']."\" file \"".$event['execute']['path']."\" not exists");
            slog("INFO","Remove \"".$event['name']."\" event");
            $this->remove($event['name']);
            return false;
        }
        include $event['execute']['path'];
        if($event['execute']['object']!=null and !class_exists($event['execute']['object'],false)){
            slog("ERROR","Event \"".$event['name']."\" class \"".$event['execute']['object']."\" not fount in file \"".$event['execute']['path']."\"");
            slog("INFO","Remove \"".$event['name']."\" event");
            $this->remove($event['name']);
            return false;
        }
        $execute = new $event['execute']['object']();
        if($event['execute']['method']!=null and !method_exists($execute,$event['execute']['method'])){
            slog("ERROR","Event \"".$event['name']."\" method \"".$event['execute']['method']."\" not fount in file \"".$event['execute']['path']."\"");
            slog("INFO","Remove \"".$event['name']."\" event");
            $this->remove($event['name']);
            return false;
        }
        if($event['type']==0)
            $this->remove($event['name']);
        //var_dump($event['execute']['params']);
        call_user_func_array([$execute,$event['execute']['method']],$event['execute']['params']);

        if($event['thread']) exit(\srv::SRV_ESUCCESS);
    }
}
