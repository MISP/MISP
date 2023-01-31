<?php

namespace CommonTools;
use Cake\ORM\Locator\LocatorAwareTrait;

class CommonTools
{
    public function connect($connection1, $connection2, $params): bool
    {

    }

    public function connection_test($connection1, $connection2): bool
    {
        return true;
    }

    public function getConnectors(): array
    {
        return $this->connects;
    }
}

?>
