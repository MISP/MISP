function getShortcutsDefinition() {
    var shortcuts = [
        {
            "key": "l",
            "description": "Go to event list",
            "action": function () {
                document.location.href = baseurl + '/events/index';
            }
        },
        {
            "key": "e",
            "description": "Go to add event page",
            "action": function () {
                document.location.href = baseurl + '/events/add';
            }
        }
    ];

    var $body = $(document.body);
    if ($body.data('controller') === 'events' && $body.data('action') === 'view') {
        shortcuts.push({
            "key": "t",
            "description": "Open the tag selection modal",
            "action": function () {
                $('.addTagButton').first().click();
            }
        });
        shortcuts.push({
            "key": "f",
            "description": "Open the freetext import modal",
            "action": function () {
                $('#freetext-button').click();
            }
        });
        shortcuts.push({
            "key": "a",
            "description": "Add an attribute",
            "action": function () {
                $('#create-button').click();
            }
        });
        shortcuts.push({
            "key": "s",
            "description": "Focus the filter attribute bar",
            "action": function () {
                $('#quickFilterField').focus();
            }
        });
    }

    if ($body.data('controller') === 'events' && $body.data('action') === 'index') {
        shortcuts.push({
            "key": "s",
            "description": "Focus the filter events bar",
            "action": function () {
                $('#quickFilterField').focus();
            }
        });
    }
    return shortcuts;
}
