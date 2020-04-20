<?php
    if (isset($field['parent'])) {
        echo h($field['parent']);
    } else {
        echo $this->element('/genericElements/IndexTable/Fields/generic_field', array(
            'row' => $row,
            'field' => $field
        ));
    }
    $extendsData = Hash::extract($row, $field['fields']['extendby_data_path']);
?>
<?php if (!empty($extendsData)): ?>
    <?php
        if (!isset($extendsData[0])) {
            $extendsData = array($extendsData);
        }
    ?>

        <?php foreach ($extendsData as $extendData): ?>
            <?php
                if (isset($field['title'])) {
                    $linkTitle = $field['title'];
                } else {
                    $linkTitle = Hash::extract($extendData, $field['fields']['extendby_link_title']);
                    if (!empty($linkTitle)) {
                        $linkTitle = $linkTitle[0];
                    }
                }
            ?>
            <div>
                <span class="apply_css_arrow">
                    <i class="<?php echo $this->FontAwesome->findNamespace('code-branch'); ?> fa-code-branch fa-rotate-180 fa-flip-vertical"></i>
                    <span style="margin-left: 0.2em;">
                        <?php 
                            echo $this->element('genericElements/IndexTable/Fields/links', array(
                                'row' => $extendData,
                                'field' => array(
                                    'url' => $baseurl . '/galaxies/view/%s',
                                    'data_path' => $field['fields']['extendby_link_path'],
                                    'title' => $linkTitle
                                ),
                            ));
                        ?>
                    </span>
                </span>
            </div>
        <?php endforeach; ?>
<?php endif; ?>