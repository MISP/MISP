<?php
    /*
     *  This template creates a root element in the menu and serves as the composition engine for its contents
     *  Passed elements can either be a dropdown element (if it has children) or a simple button (if not)
     *  the format is as described:
     *  array(
     *     'url' => 'url, if the root itself should be clickable',
     *     'text' => 'The text displayed on the button (sanitised here)',
     *     'html' => 'directly pass HTML (such as an image) as the display for the button (has to be sanitised elsewhere).
     *               The HTML option always prepends the text and both are displayed if set.',
     *     'requirement' => 'the conditions under which this element should be displayed',
     *     'children' => 'A list containing one array for each element. Element can be either a single element or an expandable group
                         The format of the arrays is described in global_menu_single and global_menu_group.'
     *  )
     */
    if (!isset($data['requirement']) || $data['requirement']) {
        if (empty($data['url'])) {
            $data['url'] = '#';
        } else if (strpos($data['url'], '://') !== null) {
            $data['url'] = h($data['url']);
        } else {
            $data['url'] = $baseurl . h($data['url']);
        }
        $child_data = '';
        if (!empty($data['children'])) {
            foreach ($data['children'] as $child) {
                $child_data .= $this->element('/genericElements/GlobalMenu/global_menu_' . (empty($child['type']) ? 'single' : $child['type']), array('data' => $child));
            }
        }

        if ($data['url'] === '#' && !empty($data['children']) && empty($child_data)) {
            return;
        }

        if (!empty($child_data)) {
            $child_data = sprintf('<ul class="dropdown-menu">%s</ul>', $child_data);
        }

        echo (sprintf(
            '<li %s><a href="%s" %s>%s%s</a>%s</li>',
            (empty($data['children']) ? '' : 'class="dropdown"'),
            (empty($data['url']) ? '#' : h($data['url'])),
            (empty($data['children']) ? '' : 'class="dropdown-toggle" data-toggle="dropdown"'),
            (empty($data['html']) ? '' : $data['html']),
            (empty($data['text']) ? '' : h($data['text'])),
            $child_data
        ));
    }
?>
