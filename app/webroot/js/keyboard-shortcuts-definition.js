function getShortcutsDefinition(controller, action) {
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
        },
        {
            "key": "?",
            "description": "Show this help",
            "action": function () {
                $('#triangle').click();
            }
        }
    ];

    if (controller === 'events' && action === 'view') {
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
    } else if (controller === 'events' && action === 'index') {
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
