<?php
App::uses('AppHelper', 'View/Helper');
App::uses('ExtensionEventColour', 'Tools');

/**
 * View wrapper around the ExtensionEventColour lib, so a template can pull the
 * palette of an origin event in an extended / extending view with
 * $this->ExtensionEventColour->assign($eventId, $ids) — or a single one with
 * ->palette($index) / ->selfPalette().
 */
class ExtensionEventColourHelper extends AppHelper
{
    /**
     * @param int   $primaryId
     * @param array $eventIds
     * @return array see ExtensionEventColour::assign()
     */
    public function assign($primaryId, array $eventIds)
    {
        return ExtensionEventColour::assign($primaryId, $eventIds);
    }

    /**
     * @param int $index
     * @return array see ExtensionEventColour::palette()
     */
    public function palette($index)
    {
        return ExtensionEventColour::palette($index);
    }

    /**
     * @return array see ExtensionEventColour::selfPalette()
     */
    public function selfPalette()
    {
        return ExtensionEventColour::selfPalette();
    }
}
