<?php
    /*
     *  This template creates a single entry within a menu group
     *  The accepted objects are as follows:
     *  array(
     *     'url' => 'url, if the root itself should be clickable',
     *     'text' => 'The text displayed on the button (sanitised here)',
     *     'requirement' => 'the conditions under which this element should be displayed',
     *     'html' => 'directly pass HTML (such as an image) as the display for the button (has to be sanitised elsewhere).
     *               The HTML option always prepends the text and both are displayed if set.'
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
         echo sprintf(
             '<li><a href="%s">%s%s</a></li>',
             $data['url'],
             (empty($data['html']) ? '' : $data['html']),
             (empty($data['text']) ? '' : h($data['text']))
         );
     }
?>
