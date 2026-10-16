<?php
// Overmind events index: analyst graphs, reports, sightings, proposals, discussions — when there are some.
if (empty($row['EventCard'])) {
    return;
}
echo '<div class="te-xtra">' . implode('', $this->EventIndex->extras($row['Event'], $row['EventCard']['graphs'])) . '</div>';
