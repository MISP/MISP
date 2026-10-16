<?php
// Overmind events index: the distribution as its icon, the level or sharing group in the tooltip.
if (empty($row['EventCard'])) {
    return;
}
echo $this->EventIndex->distribution($row['EventCard']['distribution']);
