<?php
    echo sprintf(
        '<h4>Organisation restrictions</h4>'
    );
    $options = '';
    foreach ($orgs as $org_id => $org_name) {
        $options .= sprintf(
            '<option value="%s">%s</option>',
            h($org_id),
            h($org_name)
        );
    }
    $select = sprintf(
        '<select id="OrgPickerEntry" style="margin-bottom:0px;>%s</select>',
        $options
    );
    $addOrgButton = '<span class="OrgPickerEntrySubmit btn btn-inverse"">' . __('Add') . '</span>';
    echo sprintf(
        '<div id="OrgPickerEntryList" class="tag-list-container" style="margin-bottom:10px;"></div>'
    );
    echo sprintf(
        '<div style="margin-bottom:10px;">%s %s</div><div class="clear"></div>',
        $select,
        $addOrgButton
    );
    $orgPickerEntryList = array();
    if (!empty($this->request->data['Sightingdb']['org_id'])) {
        foreach ($this->request->data['Sightingdb']['org_id'] as $org) {
            $orgPickerEntryList[$org] = $orgs[$org];
        }
    }
?>
<script type="text/javascript">
    var orgPickerEntryList = <?php echo !empty($orgPickerEntryList) ? json_encode($orgPickerEntryList, true) : '{}'; ?>;
    $('.OrgPickerEntrySubmit').click(function() {
        addOrgPickerEntryRestriction($('#OrgPickerEntry').val(), $('#OrgPickerEntry option:selected').text());
    });

    function addOrgPickerEntryRestriction(value, text, skipList) {
        if (skipList || !(value in orgPickerEntryList)) {
            if (!skipList) {
                orgPickerEntryList[value] = text;
            }
            addOrgPickerEntryToView(value, text);
        }
        var tempEntryList = [];
        for (key in orgPickerEntryList) {
            tempEntryList.push(key);
        }
        $('.org-id-picker-hidden-field').val(tempEntryList.join(','));
    }

    function reloadOrgPickerEntries(skipList = false) {
        $('.org-id-picker-hidden-field').val('');
        $('#OrgPickerEntryList').empty();
        for (var key in orgPickerEntryList) {
            addOrgPickerEntryRestriction(key, orgPickerEntryList[key], skipList);
        }
    }

    function addOrgPickerEntryToView(value, text) {
        $('#OrgPickerEntryList')
        .append(
            $("<span>")
            .attr('class', 'tag-container')
            .append(
                $("<span>").text(text)
                .attr('class', 'nowrap tag white background-blue')
            )
            .append(
                $("<span>")
                .click(function() {
                    removeOrgPickerEntry($(this).data('id'));
                })
                .attr('data-id', value)
                .text('x')
                .attr('class', 'black-white tag useCursorPointer noPrint')
            )
        );
    }

    function removeOrgPickerEntry(id) {
        delete orgPickerEntryList[id];
        reloadOrgPickerEntries(true);
    }

    $(document).ready(function() {
        for (var key in orgPickerEntryList) {
            addOrgPickerEntryRestriction(key, orgPickerEntryList[key], true);
        }
    });
</script>
