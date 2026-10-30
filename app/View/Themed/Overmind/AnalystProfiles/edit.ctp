<?php
/**
 * The editor, in the view's frame: the same tabs and section cards with
 * their inputs live, and a rail that stays on screen with the save, whom
 * the profile scores, and the value under assessment.
 *
 * The rail's bench is the bet: it is recomputed on every change, so
 * changing a weight and not looking at what it did is not a thing the
 * page lets you do. Everything sits in one form, which the recompute
 * posts as it stands and Save submits.
 *
 * @var array $profile
 * @var string|null $value
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile'),
    'js' => array('analyst-profile', 'analyst-profile-help'),
));
echo $this->element('AnalystProfiles/profile_header', array(
    'lead' => __('Your copy of the scoring rules. Edit a section; the value'
        . ' under assessment in the rail is rescored as you go.'),
));
?>
<?= $this->Form->create('AnalystProfile', array(
    'id' => 'ap-form',
    'data-ap-unsaved' => __('unsaved'),
    /*
     * No `?value=` on the simulate URL. The value under assessment rides
     * in the hidden field below, which the recompute posts, and
     * `__requestedValue()` prefers the query when there is one.
     */
    'data-ap-simulate' => $this->Html->url(array(
        'action' => 'simulate',
        $profile['id'],
    )),
    // A string from the helper every link uses: given an array, Form->create underscores the controller.
    'url' => $this->Html->url(array(
        'action' => 'edit',
        $profile['id'],
        '?' => $value === null ? array() : array('value' => $value),
    )),
)) ?>
    <input type="hidden" id="ap-bench-value"
           name="data[AnalystProfile][b64value]"
           value="<?= $value === null ? '' : h(ValueUrlTool::encode($value)) ?>">
    <div class="ap-page ap-view ap-edit">
        <div class="container-fluid">
            <div class="ap-editing" role="status">
                <i class="fas fa-pen-to-square" aria-hidden="true"></i>
                <span class="ap-editing-t"><b><?= h(__('Editing.')) ?></b> <?= h(
                    __('Nothing is kept until you save: please save your changes'
                        . ' before leaving this page.')) ?></span>
                <span class="badge text-bg-warning" data-ap-unsaved-count
                      data-one="<?= h(__('1 unsaved change')) ?>"
                      data-many="<?= h(__('%s unsaved changes')) ?>" hidden></span>
            </div>
        </div>
        <?= $this->element('AnalystProfiles/profile_tabs', array(
            'editable' => true,
            'rail' => array(
                'AnalystProfiles/edit_actions',
                'AnalystProfiles/view_scores',
                'AnalystProfiles/view_about',
                'AnalystProfiles/view_bench',
            ),
        )) ?>
    </div>
<?= $this->Form->end() ?>
