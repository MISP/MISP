<?php
/**
 * What the Collaboration tab's pill reads: notes plus opinions, empty at
 * zero. value-intelligence.js copies it across from whichever panel
 * carrying it arrives first.
 *
 * @var array $counts From ValueIntelligence::analystContext
 */
$notes = (int)$counts['notes'];
$opinions = (int)$counts['opinions'];
$written = $notes + $opinions;
?>
<span class="d-none"
      data-vp-analyst-badge="<?= $written > 0 ? h(number_format($written)) : '' ?>"
      data-vp-analyst-badge-title="<?= h(sprintf(
          __('%1$s, %2$s'),
          __n('%s note', '%s notes', $notes, $notes),
          __n('%s opinion', '%s opinions', $opinions, $opinions)
      )) ?>"></span>
