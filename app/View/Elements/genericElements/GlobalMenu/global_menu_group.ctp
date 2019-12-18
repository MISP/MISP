<?php
    /*
     *  This template creates a group entry within a menu group
     *  The accepted objects are as follows:
     *  array(
     *     'text' => 'The text displayed on the button (sanitised here)',
     *     'requirement' => 'the conditions under which this element should be displayed',
     *     'html' => 'directly pass HTML (such as an image) as the display for the button (has to be sanitised elsewhere).
     *               The HTML option always prepends the text and both are displayed if set.',
     *     'children' => 'list of child single elements that will expand a menu option into a second dropdown list'
     *  )
     */
     $child_data = '';
     foreach ($data['children'] as $child) {
         $child_data .= $this->element('/genericElements/GlobalMenu/global_menu_single', array('data' => $child));
     }
     if (!isset($data['requirement']) || $data['requirement']) {
         echo sprintf(
             '<li class="dropdown-submenu"><a tabindex="-1" href="#">%s%s</a><ul class="dropdown-menu">%s</ul></li>',
             (empty($data['html']) ? '' : h($data['html'])),
             (empty($data['text']) ? '' : h($data['text'])),
             $child_data
         );
     }
?>
