<div class="attributes index">
    <h2><?php echo __('Attributes'); ?></h2>
        <?php
            if ($isSearch == 1) {
                // The following block should serve as an example and food
                // for thought on how to optimize i18n & l10n (especially for languages that are not SOV)
                echo "<h4>" . __("Results for all attributes");
                if ($keywordSearch != null) echo __(" with the value containing "). "\"<b>" . h($keywordSearch) . "</b>\"";
                if ($attributeTags != null) echo __(" being tagged with ") ."\"<b>" . h($attributeTags) . "</b>\"";
                if ($keywordSearch2 != null) echo __(" from the events ") . "\"<b>" . h($keywordSearch2) . "</b>\"";
                if ($tags != null) echo " from events tagged \"<b>" . h($tags) . "</b>\"";
                if ($categorySearch != "ALL") echo __(" of category ") . "\"<b>" . h($categorySearch) . "</b>\"";
                if ($typeSearch != "ALL") echo __(" of type ") . "\"<b>" . h($typeSearch) . "</b>\"";
                if (isset($orgSearch) && $orgSearch != '' && $orgSearch != null) echo __(" created by the organisation ") . "\"<b>" . h($orgSearch) . "</b>\"";
                echo ":</h4>";
            }
        ?>
    <div class="pagination">
        <ul>
        <?php
        $this->Paginator->options(array(
            'update' => '.span12',
            'evalScripts' => true,
            'before' => '$(".progress").show()',
            'complete' => '$(".progress").hide()',
        ));

            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
    <table class="table table-striped table-hover table-condensed">
    <tr>
            <th><?php echo $this->Paginator->sort('event_id');?></th>
            <?php if (Configure::read('MISP.showorg') || $isAdmin): ?>
            <th><?php echo $this->Paginator->sort('org_id', 'Org');?></th>
            <?php endif; ?>
            <th><?php echo $this->Paginator->sort('category');?></th>
            <th><?php echo $this->Paginator->sort('type');?></th>
            <th><?php echo $this->Paginator->sort('value');?></th>
            <th>Tags</th>
            <th><?php echo $this->Paginator->sort('comment');?></th>
            <th<?php echo ' title="' . $attrDescriptions['signature']['desc'] . '"';?>>
            <?php echo $this->Paginator->sort('IDS');?></th>
            <th class="actions">Actions</th>
    </tr>
    <?php
    $currentCount = 0;
    if ($isSearch == 1) {

        // sanitize data
        if (isset($keywordArray)) {
            foreach ($keywordArray as &$keywordArrayElement) {
                $keywordArrayElement = h($keywordArrayElement);
            }
        // build the $replacePairs variable used to highlight the keywords
        $replacePairs = $this->Highlight->build_replace_pairs($keywordArray);
        }
    }

foreach ($attributes as $attribute):
    ?>
    <tr>
        <td class="short">
            <div ondblclick="document.location='<?php echo $baseurl?>/events/view/<?php echo $attribute['Event']['id'];?>';" title="<?php echo h($attribute['Event']['info']); ?>">
            <?php
                if ($attribute['Event']['orgc_id'] == $me['org_id']) {
                    $style='style="color:red;"';
                } else {
                    $style='';
                }
                $currentCount++;
            ?>
                <a href="<?php echo $baseurl;?>/events/view/<?php echo $attribute['Event']['id'];?>" <?php echo $style;?>><?php echo $attribute['Event']['id'];?></a>
            </div>
        </td>
        <?php if (Configure::read('MISP.showorg') || $isAdmin): ?>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl;?>/events/view/<?php echo $attribute['Event']['id'];?>'">
            <?php
        echo $this->OrgImg->getOrgImg(array('name' => $attribute['Event']['Orgc']['name'], 'id' => $attribute['Event']['orgc_id'], 'size' => 24));
            ?>
            &nbsp;
        </td>
        <?php endif;?>
        <td title="<?php echo $categoryDefinitions[$attribute['Attribute']['category']]['desc'];?>" class="short" ondblclick="document.location='<?php echo $baseurl;?>/events/view/<?php echo $attribute['Event']['id'];?>';">
        <?php echo h($attribute['Attribute']['category']); ?>&nbsp;</td>
        <td title="<?php if (isset($typeDefinitions[$attribute['Attribute']['type']])) echo $typeDefinitions[$attribute['Attribute']['type']]['desc'];?>" class="short" ondblclick="document.location='<?php echo $baseurl;?>/events/view/<?php echo $attribute['Event']['id'];?>';">
        <?php echo h($attribute['Attribute']['type']); ?>&nbsp;</td>
        <td class="showspaces" ondblclick="document.location='<?php echo $baseurl;?>/events/view/<?php echo $attribute['Event']['id'];?>';"><?php
            $sigDisplay = nl2br(h($attribute['Attribute']['value']));
            if ($isSearch == 1 && !empty($replacePairs)) {
                // highlight the keywords if there are any
                $sigDisplay = $this->Highlight->highlighter($sigDisplay, $replacePairs);
            }
            if ('attachment' == $attribute['Attribute']['type'] || 'malware-sample' == $attribute['Attribute']['type']) {
                if ($attribute['Attribute']['type'] == 'attachment' && isset($attribute['Attribute']['image'])):
                    $extension = explode('.', $attribute['Attribute']['value']);
                    $extension = end($extension);
                    $uri = 'data:image/' . strtolower(h($extension)) . ';base64,' . h($attribute['Attribute']['image']);
                    echo '<img class="screenshot screenshot-collapsed useCursorPointer" src="' . $uri . '" title="' . h($attribute['Attribute']['value']) . '" />';
                else:
            ?>
                    <a href="<?php echo $baseurl;?>/attributes/download/<?php echo $attribute['Attribute']['id'];?>"><?php echo $sigDisplay; ?></a>
            <?php
                endif;
            } else if ('link' == $attribute['Attribute']['type']) {
                ?><a href="<?php echo h($attribute['Attribute']['value']);?>"><?php echo $sigDisplay; ?></a><?php
            } else {
                echo $sigDisplay;
            }
            ?>
        </td>
        <td style = "max-width:200px;width:10px;">
            <?php foreach ($attribute['AttributeTag'] as $tag):
                $tagText = "&nbsp;";
                if (Configure::read('MISP.full_tags_on_attribute_index') == 1) $tagText = h($tag['Tag']['name']);
                else if (Configure::read('MISP.full_tags_on_attribute_index') == 2) {
                    if (strpos($tag['Tag']['name'], '=')) {
                        $tagText = explode('=', $tag['Tag']['name']);
                        $tagText = h(trim(end($tagText), "\""));
                    }
                    else $tagText = h($tag['Tag']['name']);
                }
                ?>
                <span class="tag useCursorPointer" style="margin-bottom:3px;background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>;" title="<?php echo h($tag['Tag']['name']); ?>" role="button" tabindex="0" aria-label="Search events tagged <?php echo h($tag['Tag']['name'])?>" onClick="document.location.href='<?php echo $baseurl; ?>/attributes/search/attributetag:<?php echo h($tag['Tag']['id']);?>';"><?php echo $tagText; ?></span>
            <?php endforeach; ?>
        </td>
        <td ondblclick="document.location ='document.location ='<?php echo $baseurl;?>/events/view/<?php echo $attribute['Event']['id'];?>';">
            <?php
            $sigDisplay = nl2br(h($attribute['Attribute']['comment']));
                if ($isSearch == 1 && !empty($replacePairs)) {
                    // highlight the keywords if there are any
                    $sigDisplay = $this->Highlight->highlighter($sigDisplay, $replacePairs);
            }
            echo $sigDisplay;
            ?>&nbsp;
        </td>
        <td class="short" ondblclick="document.location ='document.location ='/events/view/<?php echo $attribute['Event']['id'];?>';">
            <?php echo $attribute['Attribute']['to_ids'] ? 'Yes' : 'No'; ?>&nbsp;
        </td>
        <td class="short action-links">
    <?php
        if ($isSiteAdmin || ($isAclModify && $attribute['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $attribute['Event']['org_id'] == $me['org_id'])):
    ?>
            <a href="<?php echo $baseurl;?>/attributes/edit/<?php echo $attribute['Attribute']['id'];?>" class="icon-edit" title="Edit"></a><?php
            echo $this->Form->postLink('',array('action' => 'delete', $attribute['Attribute']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete this attribute?'));
        elseif ($isAclModify):
    ?>
            <a href="<?php echo $baseurl;?>/shadow_attributes/edit/<?php echo $attribute['Attribute']['id'];?>" class="icon-share" title="<?php echo __('Propose an edit'); ?>"></a>
    <?php
        endif;
    ?>
            <a href="<?php echo $baseurl;?>/events/view/<?php echo $attribute['Attribute']['event_id'];?>" class="icon-list-alt" title="<?php echo __('View'); ?>"></a>
        </td>
    </tr>
    <?php
endforeach;
    ?>
    </table>

    <p>
    <?php
    echo $this->Paginator->counter(array(
    'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
    ));
    ?>
    </p>
    <div class="pagination">
        <ul>
        <?php
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>

</div>
<?php
if ($isSearch == 1){
    $class = 'searchAttributes2';
} else {
    $class = 'listAttributes';
}
?>
<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => $class));
?>
<script type="text/javascript">
// tooltips
$(document).ready(function () {
    $("td, div").tooltip({
        'placement': 'top',
        'container' : 'body',
        delay: { show: 500, hide: 100 }
    });
    $('.screenshot').click(function() {
        screenshotPopup($(this).attr('src'), $(this).attr('title'));
    });
});
</script>
