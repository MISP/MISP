/**
 * This object deals with the front-end keyboard shortcuts and is included in every page.
 */
let keyboardShortcutsManager = {

	NAVIGATION_KEYS: ["ArrowUp", "ArrowDown", "PageUp", "PageDown", "Enter"],
	EVENTS: {
		"ArrowUp": "upArrowPressed",
		"ArrowDown": "downArrowPressed",
		"Enter": "enterPressed",
		"PageUp": "pageUpPressed",
		"PageDown": "pageDownPressed"
	},
	ESCAPED_TAG_NAMES: ["INPUT", "TEXTAREA", "SELECT"],
	shortcutKeys: new Map(),
	shortcutListToggled: false,

	/**
	 * Fetches the keyboard shortcut config files and populates this.shortcutJSON.
	 */
	init() {
		/* Codacy comment to notify that baseurl is a read-only global variable. */
		/* global baseurl */
		var $body = $(document.body);
		this.mapKeyboardShortcuts(getShortcutsDefinition($body.data('controller'), $body.data('action')));
		this.setKeyboardListener();
	},

	/**
	 * Toggles the view on the list of shortcuts at the bottom of the screen.
	 */
	onTriangleClick() {
		let activated = this.shortcutListToggled;
		let shortcutListElement = $('#shortcutsListContainer');
		let triangleElement = $('#triangle');
		let shortcutListElementHeight = shortcutListElement.height();
		shortcutListElement.css('top', activated ? '' : '-' + shortcutListElementHeight + 'px');
		triangleElement.css('bottom', activated ? '' : shortcutListElementHeight + 30 + 'px');
		this.shortcutListToggled = !activated;
	},

	/**
	 * Creates the HTML list of shortcuts for the user to read and sets it in the DOM.
	 */
	addShortcutListToHTML() {
		let html = "<ul>";
		for (let shortcut of this.shortcutKeys.values()) {
			html += `<li><strong>${shortcut.key.toUpperCase()}</strong>: ${shortcut.description}</li>`
		}
		html += "</ul>"
		$('#shortcuts').html(html);
	},

	/**
	 * Sets the shortcut object list.
	 * @param {} config The shortcut JSON list: [{key: string, description: string, action: string(eval-able JS code)}]
	 */
	mapKeyboardShortcuts(config) {
		for (let shortcut of config) {
			this.shortcutKeys.set(shortcut.key, shortcut);
		}
		this.addShortcutListToHTML();
	},

	/**
	 * Sets the event to listen to and the routine to call on keypress.
	 * If it's a shortcut key, execute its code. If its a navigation
	 * key, trigger an event depending on the key.
	 */
	setKeyboardListener() {
		window.onkeyup = (keyboardEvent) => {
			if (this.shortcutKeys.has(keyboardEvent.key)) {
				let activeElement = document.activeElement.tagName;
				if (!this.ESCAPED_TAG_NAMES.includes(activeElement)) {
					this.shortcutKeys.get(keyboardEvent.key).action();
				}
			} else if (this.NAVIGATION_KEYS.includes(keyboardEvent.key)) {
				window.dispatchEvent(new CustomEvent(this.EVENTS[keyboardEvent.key], {detail: keyboardEvent}));
			}
		}
	},
}

// Inits the keyboard shortcut manager's main routine and the click event on the keyboard shortcut triangle at the bottom of the screen.
$(function(){
	keyboardShortcutsManager.init();
	$('#triangle').click(keyboardShortcutsManager.onTriangleClick);
});

