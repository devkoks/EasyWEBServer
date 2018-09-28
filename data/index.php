<?php
class index
{
    public function init($server)
    {
        var_dump($server);
        print "PHP execute";
        print <<<EOT
<form method="post" enctype="multipart/form-data">
<input type="text" name="bar">
<input type="text" name="foo">
<input type="submit">
</form>

EOT;
    }
}
