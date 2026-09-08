<?php
App::uses('GalaxyColour', 'Tools');

/**
 * Canonical colour scheme for the events merged into an extended / extending
 * event view (Overmind theme).
 *
 * In such a view an attribute, an object, a tag or a cluster may come from the
 * event you are looking at or from one of the events merged into it. Every one
 * of those origins is drawn with the same colour wherever it shows up — the
 * attribute table, the object cards, the tag and galaxy lists, the extension
 * panel — so this table is the single place the colour is decided.
 *
 * The event being viewed is deliberately colourless: it is the baseline, and
 * tinting it would drown the signal the view exists for. Merged events get
 * hues spread by the golden angle, so a handful of them stay distinguishable
 * whatever the set size. Turning a hue into CSS is delegated to
 * GalaxyColour::paletteFromHue(), so every hsl() string in the theme still
 * lives in a single file.
 */
class ExtensionEventColour
{
    /**
     * Hue of the first merged event. Kept away from the theme's own blue so a
     * foreign row never reads as chrome.
     */
    const FIRST_HUE = 25;

    /**
     * Golden angle. Successive hues land far apart for any number of events.
     */
    const STEP = 137;

    /**
     * The baseline palette of the event being viewed. Same keys as
     * GalaxyColour::paletteFromHue() so a template can use either without
     * knowing which one it got.
     *
     * @var array
     */
    private static $self = array(
        'hue'           => null,
        'badgeBg'       => '#eceef1',
        'badgeText'     => '#41464b',
        'badgeBorder'   => '#c7ccd1',
        'headerText'    => '#41464b',
        'subText'       => '#6c757d',
        'sectionBg'     => '#f6f7f9',
        'sectionBorder' => '#dee2e6',
        'tintBg'        => '#eceef1',
        'tintIcon'      => '#41464b',
        'solidBg'       => '#6c757d',
        'solidText'     => 'white',
    );

    /**
     * Palette of the event being viewed.
     *
     * @return array see GalaxyColour::paletteFromHue()
     */
    public static function selfPalette()
    {
        return self::$self;
    }

    /**
     * Palette of the Nth merged event, 0-based.
     *
     * @param int $index
     * @return array see GalaxyColour::paletteFromHue()
     */
    public static function palette($index)
    {
        return GalaxyColour::paletteFromHue(
            self::FIRST_HUE + ((int)$index * self::STEP)
        );
    }

    /**
     * Palette per event id for a whole extension set.
     *
     * The order of $eventIds decides the colours, so pass them in the order the
     * controller resolved them (viewed event first) and every context lands on
     * the same mapping.
     *
     * @param int   $primaryId id of the event being viewed
     * @param array $eventIds  every event id in the view, $primaryId included
     * @return array [event_id => palette]
     */
    public static function assign($primaryId, array $eventIds)
    {
        $palettes = array((int)$primaryId => self::selfPalette());
        $index = 0;
        foreach ($eventIds as $eventId) {
            $eventId = (int)$eventId;
            if ($eventId === (int)$primaryId) {
                continue;
            }
            $palettes[$eventId] = self::palette($index);
            $index++;
        }
        return $palettes;
    }
}
