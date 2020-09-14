<?php
    $formatDifferences = [
        __('No html support, typographer & autolinker'),
        __('An additional syntax to reference MISP Elements'),
    ];
    $shortcutsTableHeader = [__('Command'), __('Action')];
    $shortcuts = [
        ['<kbd>' . implode('</kbd><kbd>', ['ctrl', ' + ', 'space']) . '</kbd>', __('Triggers autocomplete if applicable')],
        ['<kbd>' . implode('</kbd><kbd>', ['ctrl', ' + ', 'b']) . '</kbd>', __('Makes text bold')],
        ['<kbd>' . implode('</kbd><kbd>', ['ctrl', ' + ', 'i']) . '</kbd>', __('Makes text italic')],
        ['<kbd>' . implode('</kbd><kbd>', ['ctrl', ' + ', 'm']) . '</kbd>', __('Insert a MISP Element')],
        ['<kbd>' . implode('</kbd><kbd>', ['ctrl', ' + ', 'h']) . '</kbd>', __('Makes text as header')],
    ];
    $allowedScopes = ['attribute', 'object', 'eventgraph', 'attackmatrix'];
    $allowedScopesHtml = '<code>' . implode('</code> <code>', $allowedScopes) . '</code>';

    $helpHTML = '';
    $helpHTML .= '<ul class="nav nav-tabs" id="tab-markdown-help">';
    $helpHTML .=    sprintf('<li class="active"><a href="#tab-markdown">%s</a></li>', __('Markdown format'));
    $helpHTML .=    sprintf('<li class=""><a href="#tab-editor">%s</a></li>', __('Editor shortcuts'));
    $helpHTML .=    sprintf('<li class=""><a href="#tab-plugin">%s</a></li>', __('Markdown plugin'));
    $helpHTML .= '</ul class="nav nav-tabs">';

    $helpHTML .= '<div class="tab-content">';
    $helpHTML .= '<div class="tab-pane active" id="tab-markdown">';
    $helpHTML .= sprintf('<h2>%s</h2>', __('Markdown format'));
    $helpHTML .= sprintf('<p>%s</p>', __('The suported markdown format is similar to %s with some differences:', sprintf('<a href="%s" target="_blank">GFM</a>', 'https://github.github.com/gfm/')));
    $helpHTML .= sprintf('<ul>%s</ul>',
        '<li>' . implode('</li><li>', $formatDifferences) . '</li>'
    );

    $helpHTML .= sprintf('<h2>%s</h2>', __('Markdown extended format'));
    $helpHTML .= sprintf('<p>%s</p>', __('In order to have a visually pleasant report but more importantly, avoid hardcoding elements value or IDs, MISP elements such as attributes and objects can be referenced with the following special syntax'));
    $helpHTML .= sprintf('<h4 style="text-align: center;">%s</h4>', '<code style="font-size: 14px;">@[scope](id)</code>');
    $helpHTML .= sprintf('<span>%s</span>', __('Where:'));
    $helpHTML .= sprintf('<ul>%s</ul>', implode('',[
        sprintf('<li><b>%s</b>: %s</li>', 'scope', __('Is the scope to which the ID is related.')),
        sprintf('<ul><li>%s</li></ul>', __('Can be one of the following: %s', $allowedScopesHtml)),
        sprintf('<li><b>%s</b>: %s</li>','id', __('Is the ID of the MISP element'))
    ]));
    $helpHTML .= sprintf('<span>%s</span>', __('Examples:'));
    $helpHTML .= sprintf('<ul>%s</ul>', sprintf('<li>%s</li>', implode('</li><li>', [
        '<code>@[attribute](42)</code>',
        '<code>@[object](12)</code>',
        '<code>@[eventgraph](12)</code>'
    ])));

    $helpHTML .= sprintf('<h4>%s</h4>', __('Picture from attachment attribute'));
    $helpHTML .= sprintf('<p>%s</p>', __('Syntax for pictures is like the syntax for referencing MISP elements but with two differences:'));
    $helpHTML .= sprintf('<ul>%s</ul>', sprintf('<li>%s</li>', implode('</li><li>', [
        __('The addition of the %s character to indicate that the picture should be displayed and not the atttribute', '<code>!</code>'),
        __('The scope is fixed to %s', '<code>attribute</code>')
    ])));
    $helpHTML .= sprintf('<h4 style="text-align: center;">%s</h4>', '<code style="font-size: 14px;">@![attribute](id)</code>');
    $helpHTML .= sprintf('<span>%s</span>', __('Examples:'));
    $helpHTML .= sprintf('<ul>%s</ul>', sprintf('<li>%s</li>', implode('</li><li>', [
        '<code>@![attribute](52)</code>'
    ])));
    $helpHTML .= sprintf('<h4>%s</h4>', __('Event\'s ATT&CK matrix'));
    $helpHTML .= sprintf('<p>%s</p>', __('Syntax for embedding the ATT&CK matrix is similar the syntax for referencing MISP elements:'));
    $helpHTML .= sprintf('<ul>%s</ul>', sprintf('<li>%s</li>', implode('</li><li>', [
        __('The scope is fixed to %s', '<code>attackmatrix</code>'),
        __('Here, the ID is irrelevant as the matrix will be taken from the whole event for which the report is linked to'),
    ])));
    $helpHTML .= sprintf('<span>%s</span>', __('Examples:'));
    $helpHTML .= sprintf('<ul>%s</ul>', sprintf('<li>%s</li>', implode('</li><li>', [
        '<code>@[attackmatrix](1)</code>'
    ])));
    $helpHTML .= '</div>';

    $helpHTML .= '<div class="tab-pane" id="tab-editor">';
    $helpBodyHTML = '';
    foreach ($shortcuts as $sc) {
        $helpBodyHTML .= sprintf('<tr><td><kbd>%s</kbd></td><td>%s</td></tr>', $sc[0], $sc[1]);
    }
    $helpHTML .= sprintf('<h2>%s</h2>', __('Editor shortcuts'));
    $helpHTML .= sprintf('<table class="table table-bordered table-condensed"><thead><tr>%s</tr></thead><tbody>%s</tbody></table>',
        '<th>' . implode('</th><th>', $shortcutsTableHeader) . '</th>',
        $helpBodyHTML
    );
    $helpHTML .= '</div>';

    $helpHTML .= '<div class="tab-pane" id="tab-plugin">';
    $helpHTML .= sprintf('<h2>%s</h2>', __('Markdown plugins'));
    $helpHTML .= sprintf('<h3>%s</h3>', __('Highlighted language'));
    $helpHTML .= sprintf('<p>%s</p>', __('Languages rendered in code block can be highlighted using the %s plugin. The list of supported languages can be found %s.',
        sprintf('<a href="%s">%s</a>', 'https://highlightjs.org/', 'highlight.js'),
        sprintf('<a href="%s">%s</a>', 'https://github.com/highlightjs/highlight.js/blob/master/SUPPORTED_LANGUAGES.md', 'here')
    ));

    $helpHTML .= '</div>';

    $helpHTML .= '</div>';

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

<script>
    $('#tab-markdown-help a').click(function (e) {
        e.preventDefault();
        $(this).tab('show');
    })
</script>

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