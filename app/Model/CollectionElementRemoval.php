<?php
App::uses('AppModel', 'Model');

/**
 * A member partners still hold, taken out of its collection since the
 * collection was last published.
 */
class CollectionElementRemoval extends AppModel
{
    public $recursive = -1;
}
