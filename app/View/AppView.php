<?php
class AppView extends View
{
    /**
     * Negative results of `file_exists` methods are not cached, so we provide our cache
     * @var array
     */
    private $elementFileCache = [];

    /**
     * @param string $name
     * @return false|string
     */
    protected function _getElementFileName($name)
    {
        if (isset($this->elementFileCache[$name])) {
            return $this->elementFileCache[$name];
        }
        $result = parent::_getElementFileName($name);
        $this->elementFileCache[$name] = $result;
        return $result;
    }
}
