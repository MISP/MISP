<?php
/*
 * A collection's members, read-only: its page's elements card, drawn bare
 * for the popover the query console opens on a collection.
 */
echo $this->element('Collections/View/collection_elements_card', [
    'data' => $data,
    'isSiteAdmin' => false,
    'mayModify' => false,
]);
