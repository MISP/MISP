<?php
App::uses('AppHelper', 'View/Helper');
App::uses('ModalAccent', 'Tools');

/**
 * View wrapper around the ModalAccent lib, so a template can pull the canonical
 * look of a scope with $this->ModalAccent->get('tag').
 */
class ModalAccentHelper extends AppHelper
{
    /**
     * @param string $accent accent key ('tag', 'galaxy', 'warninglist', …)
     * @return array see ModalAccent::get()
     */
    public function get($accent)
    {
        return ModalAccent::get($accent);
    }

    /**
     * @return array see ModalAccent::keys()
     */
    public function keys()
    {
        return ModalAccent::keys();
    }
}
