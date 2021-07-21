<div id="tagList">
    <label><?php echo __('Tags'); ?></label>
    <table>
        <tr>
            <td>
                <table>
                    <tr id="tags"></tr>
                </table>
            </td>
            <td id="addTagButtonTD">
                <button type="button" onClick="activateTagField()" id="addTagButton" title="<?php echo __('Add tag'); ?>" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;">+</button>
            </td>
            <td id="addTagFieldTD">
                <?php
                echo ($this->Form->input($fieldData['field'], array('id' => 'hiddenTags', 'div' => 'clear', 'label' => false, 'type' => 'text', 'value' => '[]', 'style' => 'display:none;')));
                echo $this->Form->input('tagsPusher', array(
                    'div' => 'clear',
                    'id' => 'addTagField',
                    'options' => array($fieldData['tags']),
                    'label' => false,
                    'onChange' => 'tagFieldChange()',
                    'style' => "height:22px;padding:0px;margin-bottom:0px;display:none;",
                    'empty' => __('Add a tag'),
                ));
                ?>
            </td>
        </tr>
    </table>
</div>
<script type="text/javascript">
    var selectedTags = [
        <?php
        foreach ($fieldData['selectedTags'] as $k => $t) {
            if ($k != 0) echo ', ';
            echo '"' . h($t['Tag']['id']) . '"';
        }
        ?>
    ];
    var allTags = [
        <?php
        foreach ($fieldData['tagInfo'] as $tag) {
            echo "{'id' : '" . h($tag['Tags']['id']) . "', 'name' : '" . h($tag['Tags']['name']) . "', 'colour' : '" . h($tag['Tags']['colour']) . "'},";
        }
        ?>
    ];
    $(document).ready(function() {
        for (var i = 0, len = selectedTags.length; i < len; i++) {
            appendTemplateTag(selectedTags[i], 'yes');
        }
    });
</script>
<?php echo $this->Js->writeBuffer();
