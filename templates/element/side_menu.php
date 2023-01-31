<?php
if (empty($minimal)) {
    $element = 'side_menu_scaffold';
} else {
    $element = 'side_menu_dropdown_scaffold';
}
echo $this->element('genericElements/' . $element, ['menu' => $menu]);
