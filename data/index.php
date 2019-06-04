<?php
class index
{
    public function init($server)
    {
        if(isset($server['FILES']['fiole'])){
            var_dump($server['FILES']['fiole']['content']);
        }
        print "PHP execute";
        print <<<EOT
<form method="post" enctype="multipart/form-data">
<input type="text" name="bar">
<input type="text" name="foo">
<input type="file" name="fiole">
<input type="submit">
</form>
<script src="test.js"></sctipt>

EOT;
    }
}
