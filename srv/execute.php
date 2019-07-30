<?php
namespace srv;
class execute
{
    private $__url     = "/";
    private $__headers = [];
    private $__content = "";
    private $__client  = [];

    private $isBuffer = false;
    private $context;
    private $conf;
    private $return;

    public function __construct($context,$client,$ip)
    {
        $content = "";

        $this->context = $context;
        $this->conf = $this->context->getConf();
        $this->__client["content"] = $client;
        $this->__client["addr"] = $ip;

        $this->parseClientContent();
        $this->header("HTTP/1.1 200 OK");
        $this->header("Server: EasyServer 0.1");
        if($this->select() == "application/x-httpd-php"){
            $this->__content = $this->run();
            $this->header("Content-type: text/html");
        }else{
            $dir = $this->conf["start"]["dir"].parse_url($this->__url,PHP_URL_PATH);
            if(!file_exists($dir)){
                $dir = $this->conf["error-page"]["404"];
            }
            $this->header("Content-type: ".$this->select());
            $size = filesize($dir);
            if($size!=0){
                $f=fopen($dir,"r");
                $this->__content = fread($f,$size);
                fclose($f);
                $ETag = md5($this->__content);
                $this->header("Date: ".date("r"));
                $this->header("ETag: ".$ETag);
                if(isset($this->__client["headers"]["If-None-Match"])){
                    if($this->__client["headers"]["If-None-Match"]==$ETag){
                        $this->status(304,"Not Modified");
                        $this->__content = "";
                    }else{
                        $this->header("Accept-Ranges: bytes");
                        $this->header("Content-Length: ".strlen($this->__content));
                    }
                }else{
                    $this->header("Accept-Ranges: bytes");
                    $this->header("Content-Length: ".strlen($this->__content));
                }
            }
            unset($size,$dir,$f);
        }
        $headers="";
        foreach($this->__headers as $header)
            $headers .= $header;
        $this->return = $headers.PHP_EOL.$this->__content;
        return $this->return;
    }

    public function header($header)
    {
        if(strpos($header,'Location')!==false)
            $this->status(302,'Moved Temporarily');
        $this->__headers[] = $header.PHP_EOL;
    }

    public function status($code,$name)
    {
        $this->__headers[0] = 'HTTP/1.1 '.$code.' '.$name.PHP_EOL;
    }

    public function disableBuffer()
    {
        $this->isBuffer = false;
    }

    public function setContent($content)
    {
        $this->__content = $content;
    }

    public function getReturn()
    {
        return $this->return;
    }

    private function select()
    {
        $url = parse_url($this->__url,PHP_URL_PATH);
        $extension = substr($url, strrpos($url, ".") + 1);
        return isset($this->conf["mime-types"][$extension]) ? $this->conf["mime-types"][$extension] : $this->conf["mime-types"]["*"];
    }

    private function run()
    {
        $return="";
        $class = $this->conf["start"]["class"];
        $method = $this->conf["start"]["method"];
        $data = $this->server();
        $data['SERVER']['__IPC'] = $_SERVER['__IPC'];
        $_SERVER = $data['SERVER'];
        $_SERVER['__SRV'] = $this;
        $_GET = $data['GET'];
        $_POST = $data['POST'];
        $_COOKIE = $data['COOKIE'];
        $_FILES = $data['FILES'];
        if($this->isBuffer){
            ob_start();
            $index = new $class();
            $index->$method($data);
            return ob_get_clean();
        }else{
            $index = new $class();
            $index->$method($data);
            return $this->__content;
        }

    }

    private function server()
    {
        return [
            "SERVER"=>[
                //"LOCAL_PORT"=>$this->context->__port,
                "REMOTE_ADDR"=>$this->__client["addr"],
                "PROTOCOL"=>$this->__client["protocol"],
                "REQUEST_TYPE"=>$this->__client["request-type"],
                "REQUEST_URI"=>$this->__url,
                "REQUEST_TIME"=>time()
            ],
            "CLIENT"=>[
                "headers"=>$this->__client["headers"],
                "body"=>$this->__client["body"]
            ],
            "GET"=> (is_null(parse_url($this->__url,PHP_URL_QUERY))) ? [] : $this->parseUrlQuery($this->__url),
            "POST"=>$this->post(),
            "COOKIE"=>$this->cookie(),
            "FILES"=>$this->files()
        ];
    }

    private function parseUrlQuery($url)
    {
        $GET = urldecode(parse_url($url,PHP_URL_QUERY));
        if(empty($GET)){
            parse_str($url,$GET);
        }
        return $GET;
    }
    private function post()
    {
        if(!isset($this->__client["headers"]["Content-Type"])) return [];
        switch($this->__client["headers"]["Content-Type"]){
            case "application/x-www-form-urlencoded":
                return $this->parseUrlQuery($this->__client["body"]);
            break;
            case "text/plain":
                return [$this->__client["body"]];
            break;
            default:
                $header = explode(";",$this->__client["headers"]["Content-Type"]);
                if(isset($header[1]) and !empty($header[1])){
                    switch($header[0]){
                        case "multipart/form-data":
                            $return = [];
                            $params = $this->parseBoundaryContent($this->__client["headers"]["Content-Type"],$this->__client["body"]);
                            foreach($params as $name => $param){
                                if(!isset($param["headers"]["Content-Disposition"]["filename"])){
                                    $return[$name] = $param["body"];
                                }
                            }
                            return $return;
                        break;
                        default:
                        return [];
                    }
                }
        }

        return [];
    }
    private function cookie()
    {
        $cookies = [];
        if(isset($this->__client["headers"]["Cookie"])){
            $cookiesHeader = explode(";",$this->__client["headers"]["Cookie"]);
            foreach($cookiesHeader as $cookieHeader){
                $cookie = explode("=",$cookieHeader);
                $cookies[trim($cookie[0])]=trim($cookie[1]);
            }
        }
        return $cookies;
    }

    private function files()
    {
        if(!isset($this->__client["headers"]["Content-Type"])) return [];
        $files = [];
        $posts = $this->parseBoundaryContent($this->__client["headers"]["Content-Type"],$this->__client["body"]);
        foreach($posts as $name => $post){
            if(isset($post["headers"]["Content-Disposition"]["filename"])){
                $files[$name]["filename"] = $post["headers"]["Content-Disposition"]["filename"];
                $files[$name]["content"] = $post["body"];
            }
        }
        return $files;
    }

    private function parseClientContent()
    {
        $content = explode("\r\n\r\n",$this->__client["content"]);

        $h=$content[0];
        unset($content[0]);

        $content[1] = implode("\r\n\r\n",$content);
        $content[0] = $h;

        if(isset($content[0])){
            $headers = $content[0];
            $headers = explode(PHP_EOL,$headers);
            $http = explode(" ",trim($headers[0]));
            $this->__url = $http[1];
            $this->__client["protocol"] = $http[2];
            $this->__client["request-type"] = $http[0];
            foreach($headers as $header){
                $hh = explode(":",$header);
                if(!empty(trim($hh[0])))
                    $this->__client["headers"][trim($hh[0])] = (isset($hh[1])) ? trim($hh[1]) : true;
            }
        }
        if(isset($content[1])){
            $this->__client["body"] = $content[1];
        }else{
            $this->__client["body"] = "";
        }
    }
    private function parseBoundaryContent($type,$content)
    {
        $type = explode(";",$type);
        if(!isset($type[1])) return [];

        //Parsing boundary name
        preg_match('/boundary\=(.*)/',$type[1],$boundary);
        $boundary = $boundary[1];

        $content = str_replace("--".$boundary."--","",$content);

        $array = explode("--".$boundary."\r\n",$content);
        $parts = [];
        foreach($array as $arr){
            if(empty($arr)) continue;
            $headers=[];
            $heads = explode("\r\n\r\n",$arr);
            $body = $heads[1];
            $heads = explode("\r\n",$heads[0]);
            foreach($heads as $head){
                $head = trim($head);
                $header = explode(":",$head);
                foreach($header as $heade){
                    $h = explode(";",$heade);
                    foreach($h as $hs){
                        preg_match('/(.*?)\=\"(.*?)\"/',trim($hs),$hds);
                        if(empty($hds[1])) continue;
                        $headers[trim($header[0])][$hds[1]] = $hds[2];
                    }
                }
            }
            $parts[$headers["Content-Disposition"]["name"]] = ["headers"=>$headers,"body"=>$body];
        }
        return $parts;
    }

    public function error($httpCode,$content)
    {

    }

}

