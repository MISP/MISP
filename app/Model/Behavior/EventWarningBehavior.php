<?php

/**
 * Set warnings based on a set of fixed checks
 */
class EventWarningBehavior extends ModelBehavior
{
    private $__warningPackages = [];

    /**
     * @param Model $Model
     * @param array $event
     * @return array
     */
    public function generateWarnings(Model $Model, array $event)
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
        $dir = new Folder(APP . 'Lib/EventWarning' . $subDirPath);
        $files = $dir->find('.*Warning\.php');
        foreach ($files as $file) {
            $className = substr($file, 0, -4);
            $path = 'EventWarning' . $subDirPath;
            App::uses($className, $path);
            $this->__warningPackages[$className] = new $className();
        }
    }
}
