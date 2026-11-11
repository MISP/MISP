<?php
App::uses('AppHelper', 'View/Helper');
App::uses('GalaxyColour', 'Tools');

/**
 * View wrapper around the GalaxyColour lib so templates can pull a galaxy's
 * deterministic colour palette with $this->GalaxyColour->palette($name).
 */
class GalaxyColourHelper extends AppHelper
{
    /**
     * @param string $name
     * @return int
     */
    public function hue($name)
    {
        return GalaxyColour::hue($name);
    }

    /**
     * @param string $name
     * @return array see GalaxyColour::palette()
     */
    public function palette($name)
    {
        return GalaxyColour::palette($name);
    }

    /**
     * @param int $hue 0-359
     * @return array see GalaxyColour::palette()
     */
    public function paletteFromHue($hue)
    {
        return GalaxyColour::paletteFromHue($hue);
    }

    /**
     * Palette for one member of a small, fixed set of values
     *
     * @param string $value
     * @param array $list
     * @return array see GalaxyColour::palette()
     */
    public function paletteFromList($value, array $list)
    {
        $index = array_search($value, $list, true);
        return $index === false
            ? GalaxyColour::palette($value)
            : GalaxyColour::paletteFromHue((int)round($index * 137.508));
    }

    /**
     * @param string $name
     * @return string full inline style for a galaxy/cluster pill
     */
    public function badgeStyle($name)
    {
        return GalaxyColour::badgeStyle($name);
    }

    /**
     * @return string metallic sheen background-image shared by all badges
     */
    public function metallic()
    {
        return GalaxyColour::metallic();
    }
}
