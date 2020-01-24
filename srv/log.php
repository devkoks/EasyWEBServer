<?php
/**
 *
 * @param string $level Log level
 * @param string $text Log text
 * @return void
 *
*/
function slog(string $level, string $text): void
{
    if($_SERVER["LOGS_ENABLE"]==false) return;
    if(!file_exists($_SERVER["CONF"]['logs'])) mkdir($_SERVER["CONF"]['logs'],0644,true);
    $time = time();
	$date = getdate($time);
	$string = date("[d/m/Y H:i:s]",$time)."[".$level."]".$text.PHP_EOL;
    print $string;
	$logfile = fopen($_SERVER["CONF"]['logs']."/".date("d-m-Y").'.log', 'a');
	fwrite($logfile,$string);
	fclose($logfile);
}
