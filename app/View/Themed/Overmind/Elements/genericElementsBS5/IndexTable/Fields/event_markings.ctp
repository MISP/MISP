<?php
// Overmind events index: the markings the reader's analyst profile pins.
if (empty($row['EventCard'])) {
    return;
}
echo '<span class="te-marks">' . $this->EventIndex->markings($row['EventCard']['markings']) . '</span>';
