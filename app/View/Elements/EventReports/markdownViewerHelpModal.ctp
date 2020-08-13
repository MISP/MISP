<?php
    $formatDifferences = [
        __('No html support, typographer & autolinker'),
        __('An additional syntax to reference MISP Elements'),
    ];
    $shortcutsTableHeader = [__('Command'), __('Action')];
    $shortcuts = [
        ['<kbd>' . implode('</kbd><kbd>', ['&lt;ctrl&gt;', ' + ', '&lt;space&gt;']) . '</kbd>', __('Triggers autocomplete if applicable')],
        ['<kbd>' . implode('</kbd><kbd>', ['&lt;ctrl&gt;', ' + ', '&lt;b&gt;']) . '</kbd>', __('Makes text bold')],
        ['<kbd>' . implode('</kbd><kbd>', ['&lt;ctrl&gt;', ' + ', '&lt;i&gt;']) . '</kbd>', __('Makes text italic')],
    ];
    $syntaxHelp = [
        sprintf('<b>%s</b>: %s','scope', __('Is the scope you want to reference. Can be either %s or %s', sprintf('<code>%s</code>', 'attribute'), sprintf('<code>%s</code>', 'object'))),
        sprintf('<b>%s</b>: %s','id', __('Is the ID of the element')),
    ];
    $syntaxHelp2 = [
       '<code>@[attribute](42)</code>',
       '<code>@[object](12)</code>',
    ];

    $helpHTML = '';
    $helpHTML .= sprintf('<h2>%s</h2>', __('Markdown format'));
    $helpHTML .= sprintf('<p>%s</p>', __('The suported markdown format is similar to %s with some differences:', sprintf('<a href="%s">GFM</a>', 'https://github.github.com/gfm/')));
    $helpHTML .= sprintf('<ul>%s</ul>',
        '<li>' . implode('</li><li>', $formatDifferences) . '</li>'
    );

    $helpHTML .= sprintf('<h3>%s</h3>', __('Markdown extended format'));
    $helpHTML .= sprintf('<p>%s</p>', __('In order to have a visually pleasant document but more importantly avoid hard coding, MISP elements such as attributes and objects can be referenced with the following special syntax'));
    $helpHTML .= sprintf('<h4 style="text-align: center;">%s</h4>', '<code style="font-size: 14px;">@[scope](id)</code>');
    $helpHTML .= sprintf('<span>%s</span>', __('Where:'));
    $helpHTML .= sprintf('<ul>%s</ul>',
        '<li>' . implode('</li><li>', $syntaxHelp) . '</li>'
    );
    $helpHTML .= sprintf('<span>%s</span>', __('Examples:'));
    $helpHTML .= sprintf('<ul>%s</ul>',
        '<li>' . implode('</li><li>', $syntaxHelp2) . '</li>'
    );

    $helpBodyHTML = '';
    foreach ($shortcuts as $sc) {
        $helpBodyHTML .= sprintf('<tr><td><kbd>%s</kbd></td><td>%s</td></tr>', $sc[0], $sc[1]);
    }
    $helpHTML .= sprintf('<h2>%s</h2>', __('Editor shortcuts'));
    $helpHTML .= sprintf('<table class="table table-bordered table-condensed"><thead><tr>%s</tr></thead><tbody>%s</tbody></table>',
        '<th>' . implode('</th><th>', $shortcutsTableHeader) . '</th>',
        $helpBodyHTML
    );

    $data = array(
        'title' => __('Markdown viewer help'),
        'content' => array(
            array(
                'html' => $helpHTML
            ),
        )
    );
    echo $this->element('genericElements/infoModal', array('data' => $data, 'type' => 'lg', 'class' => 'markdown-modal-helper'));
?>

<style>
/* borrowing from BS4 */
kbd {
    padding: .2rem .4rem;
    font-size: 87.5%;
    color: #fff;
    background-color: #212529;
    border-radius: .2rem;
}
kbd kbd {
    padding: 0;
    font-size: 100%;
    font-weight: 700;
}
</style>