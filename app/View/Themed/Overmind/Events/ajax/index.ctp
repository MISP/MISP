<?php
echo $this->element('Events/index', [
    'events' => $events,
    'show_user_button' => false,
    'show_org_button' => false,
]);