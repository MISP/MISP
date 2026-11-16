<?php
echo $this->element('genericElements/assetLoader', [
    // events-index-cards: the event peek draws its context with the events index card's chips.
    'css' => ['attributes-index', 'events-index-cards'],
]);
echo $this->element('Attributes/index', [
    'attributes' => $attributes,
    'show_event_id' => true,
    'show_filters' => true,
]);