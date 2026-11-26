<?php
/**
 * Canonical glyph of a collection type, shared by the add/edit form's type
 * picker and the badge in front of a collection's page title.
 */
class CollectionType
{
    private static $icons = array(
        'campaign'      => 'fas fa-bullseye',
        'intrusion_set' => 'fas fa-user-secret',
        'named_threat'  => 'fas fa-skull-crossbones',
        'research'      => 'fas fa-flask',
        'other'         => 'fas fa-shapes',
    );

    /**
     * @return array type => full class attribute of its glyph
     */
    public static function icons()
    {
        return self::$icons;
    }

    /**
     * @param string $type
     * @return string full class attribute of the glyph
     */
    public static function icon($type)
    {
        return self::$icons[(string)$type] ?? 'fas fa-folder';
    }

    /**
     * @param string $type
     * @return string human-readable label ("intrusion_set" → "Intrusion set")
     */
    public static function label($type)
    {
        return ucfirst(str_replace('_', ' ', (string)$type));
    }
}
