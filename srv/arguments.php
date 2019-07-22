<?php
global $argv;
$args = implode(" ",$argv);
preg_match_all("/\-([A-z])\s(.*?)(\s|$)/m",$args,$matched,PREG_SET_ORDER, 0);
unset($args);
$args = [];
foreach($matched as $arg)
    $args[$arg[1]] = $arg[2];

return $args;
