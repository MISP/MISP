<?php
// Overmind events index: the distribution as its icon, a sharing group by name.
if (empty($row['EventCard'])) {
    return;
}
echo $this->EventIndex->distribution($row['EventCard']['distribution']);
