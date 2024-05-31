<?php

namespace App\Model\Behavior;

use App\Model\Table\AppTable;
use RegexIterator;
use DirectoryIterator;
use Cake\ORM\Behavior;

/**
 * Set warnings based on a set of fixed checks
 */
class EventWarningBehavior extends Behavior
{
    private $__warningPackages = [];

    /**
     * @param array $event
     * @return array
     */
    public function generateWarnings(array $event)
    {
        $warnings = [];
        $this->__loadCustomWarningSystems();
        $this->__loadCustomWarningSystems('Custom');
        foreach ($this->__warningPackages as $packageName => $package) {
            foreach ($package->functions as $function) {
                $package->$function($event, $warnings);
            }
        }
        return $warnings;
    }

    private function __loadCustomWarningSystems($subdir = false)
    {
        $subDirPath = $subdir ? ('/' . $subdir) : '';

        $dir = new DirectoryIterator(APP . 'Lib/EventWarning' . $subDirPath);
        $regexIterator = new RegexIterator($dir, '/.*Warning\.php$/');

        foreach ($regexIterator as $fileInfo) {
            if ($fileInfo->isFile()) {
                $className = substr($fileInfo->getFilename(), 0, -4);
                require_once ($fileInfo->getPathname());
                $this->__warningPackages[$className] = new $className();
            }
        }
    }
}
