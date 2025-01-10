<?php
App::uses('AppHelper', 'View/Helper');

class PrettyPrintHelper extends AppHelper
{

    public function ppArray($array, $depth = 0)
    {
        $text = '';
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                $value = $this->ppArray($value, $depth+1);
            } else {
                $value = h($value);
            }
            $text .= sprintf(
                '<div><span class="text-primary">%s</span>: %s</div>',
                h($key),
                $value
            );
        }
        return $text;
    }
}


?>
