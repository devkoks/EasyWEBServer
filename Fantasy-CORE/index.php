<?php
class index
{
    public function init($server){
        $CoreConf = ['start-app'=>true,'load-tpl'=>true,'load-modules'=>true,'app-dir'=>'/./'];//Параметры для подключения ядра(FastConf)
        require_once __DIR__.'/core/index.php';//Подключаем ядро которое запустит приложение
        new core($CoreConf);
    }
}
