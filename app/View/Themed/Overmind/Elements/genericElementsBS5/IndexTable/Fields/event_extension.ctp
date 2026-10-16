<?php
// Overmind events index: what the event extends, and how many events extend it.
if (empty($row['EventCard'])) {
    return;
}
echo '<span class="te-ext">' . implode(' ', $this->EventIndex->extension($row['EventCard'], true)) . '</span>';
