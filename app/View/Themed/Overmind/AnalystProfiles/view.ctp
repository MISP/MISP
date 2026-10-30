<?php
/**
 * A profile, read-only, in the frame every Overmind detail page uses: one
 * tab per family of sections, each section a card the reader folds, and
 * a rail with the actions, whom the profile scores and the value under
 * assessment.
 *
 * With `?value=` each weight is shown beside the contribution it
 * produced on that value. Without one the column stays empty rather
 * than inventing a number.
 *
 * @var array $profile
 * @var array|null $standing This profile's row of the index board
 */
echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile'),
    'js' => array('analyst-profile', 'analyst-profile-help'),
));
echo $this->element('AnalystProfiles/profile_header');
?>
<div class="ap-page ap-view">
    <?= $this->element('AnalystProfiles/profile_tabs', array(
        'editable' => false,
        'rail' => array(
            'AnalystProfiles/view_actions',
            'AnalystProfiles/view_scores',
            'AnalystProfiles/view_about',
            'AnalystProfiles/view_bench',
        ),
    )) ?>
</div>
