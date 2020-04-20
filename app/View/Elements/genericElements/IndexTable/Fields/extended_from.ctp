<?php
    if (isset($field['parent'])) {
        $generic_field_output = h($field['parent']);
    } else {
        $generic_field_output = $this->element('/genericElements/IndexTable/Fields/generic_field', array(
            'row' => $row,
            'field' => $field
        ));
    }
    if (isset($field['fields']['extendfrom_original_value'])) {
        $original_value_output = Hash::extract($row, $field['fields']['extendfrom_original_value']);
        if (!empty($original_value_output)) {
            $original_value_output = $original_value_output[0];
        }
    } else {
        $original_value_output = '';
    }
    $extendsData = Hash::extract($row, $field['fields']['extendfrom_data_path']);
    if (!empty($extendsData)) {
        if (isset($field['title'])) {
            $linkTitle = $field['title'];
        } else {
            $linkTitle = Hash::extract($extendsData, $field['fields']['extendfrom_link_title']);
            if (!empty($linkTitle)) {
                $linkTitle = $linkTitle[0];
            }
        }
        $extended_from_output = $this->element('genericElements/IndexTable/Fields/links', array(
            'row' => $extendsData,
            'field' => array(
                'url' => $baseurl . '/galaxies/view/%s',
                'data_path' => $field['fields']['extendfrom_link_path'],
                'title' => $linkTitle
            ),
        ));
        $current_value_output = $this->element('genericElements/IndexTable/Fields/links', array(
            'row' => $extendsData,
            'field' => array(
                'url' => $baseurl . '/galaxies/view/%s',
                'data_path' => $field['fields']['extendfrom_link_path'],
                'title' => $linkTitle
            ),
        ));
    } else {
       echo $generic_field_output;
    }
?>
<?php if (!empty($extendsData)): ?>
    <div>
        <div class="bold">
            <?= $extended_from_output ?> ::
            <i class="<?php echo $this->FontAwesome->findNamespace('code-branch'); ?> fa-code-branch fa-rotate-90"></i>
            <span style="margin-left: 0.2em;"><?= $original_value_output ?></span>
        </div>
        <span>
            <?= $generic_field_output ?>
        </span>
    </div>
<?php endif; ?>