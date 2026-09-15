<?php
App::uses('AppHelper', 'View/Helper');
App::uses('RoleGlyph', 'Tools');

/**
 * View wrapper around the RoleGlyph lib so templates can pull the canonical
 * look of a role with $this->RoleGlyph->get($name) — or the whole table, for
 * the ones that render every role in a loop, with ->all().
 */
class RoleGlyphHelper extends AppHelper
{
    /**
     * @return array see RoleGlyph::all()
     */
    public function all()
    {
        return RoleGlyph::all();
    }

    /**
     * @param string|array $role
     * @return array see RoleGlyph::get()
     */
    public function get($role)
    {
        return RoleGlyph::get($role);
    }

    /**
     * @return array see RoleGlyph::fallback()
     */
    public function fallback()
    {
        return RoleGlyph::fallback();
    }
}
