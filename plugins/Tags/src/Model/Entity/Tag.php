<?php

namespace Tags\Model\Entity;

use App\Model\Entity\AppModel;

class Tag extends AppModel {

    protected $_accessible = [
        'id' => false,
        'counter' => false,
        '*' => true,
    ];

    protected $_accessibleOnNew = [
        'name' => true,
        'colour' => true,
    ];

    protected $_virtual = ['text_colour'];

    protected function _getTextColour()
    {
        $textColour = null;
        if (!empty($this->colour)) {
            $textColour = $this->getTextColour($this->colour);
        }
        return $textColour;
    }

    protected function getTextColour($RGB) {
        $r = hexdec(substr($RGB, 1, 2));
        $g = hexdec(substr($RGB, 3, 2));
        $b = hexdec(substr($RGB, 5, 2));
        $average = ((2 * $r) + $b + (3 * $g))/6;
        if ($average < 127) {
            return 'white';
        } else {
            return 'black';
        }
    }

}
