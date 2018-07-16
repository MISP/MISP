/**
 * This object deals with keyboard navigation when choosing a tag using the "Select Tag" modal.
 * It relies on events dispatched by "keyboard-shortcuts.js".
 */
let keyboardTagSelection = {
	TAG_CLASS: "#popover_choice_main .templateChoiceButton.shown",
	DISPLAYED_TAGS_CLASS: "shown",
	KEYS: ["ArrowUp", "ArrowDown", "Enter"],
	SELECTED_TAG_CLASS: "selected-tag",
	PAGE_OFFSET: 5,
	selectedElement: null,
	selectedElementIndex: -1,
	elements: $(this.TAG_CLASS),
	oldElementLength: 0,

	/**
	 * Sets the event to listen to and the routine to call on keypress, if not already done.
	 */
	init() {
		if(!window.tagSelectionPopupLoaded) {
			window.tagSelectionPopupLoaded = true;
			window.addEventListener('upArrowPressed', () => this.onUpArrowPress());
			window.addEventListener('downArrowPressed', () => this.onDownArrowPress());
			window.addEventListener('pageUpPressed', () => this.onPageUpPress());
			window.addEventListener('pageDownPressed', () => this.onPageDownPress());
			window.addEventListener('enterPressed', () => this.onEnterPress());
		}
	},

	/**
	 * Selects the previous tag in the list. If reached the beginning of the list,
	 * select the last element.
	 */
	onUpArrowPress() {
		this.oldElementLength = this.elements.length;
		this.elements = $(this.TAG_CLASS);
		if(this.oldElementLength != this.elements.length) {
			if(!this.selectedElement || !this.selectedElement.hasClass(this.DISPLAYED_TAGS_CLASS)) {
				if(this.elements.length > 0) {
					this.selectPreviousTag();
				}
			} else {
				this.selectLastTag();
			}
		} else {
			this.selectPreviousTag();
		}
	},

	/**
	 * Selects the next tag in the list. If reached the end of the list,
	 * select the first element.
	 */
	onDownArrowPress() {
		this.oldElementLength = this.elements.length;
		this.elements = $(this.TAG_CLASS);
		if(this.oldElementLength != this.elements.length) {
			if(!this.selectedElement || !this.selectedElement.hasClass(this.DISPLAYED_TAGS_CLASS)) {
				if(this.elements.length > 0) {
					this.selectNextTag();
				}
			} else {
				this.selectFirstTag();
			}
		} else {
			this.selectNextTag();
		}
	},

	/**
	 * Selects a tag at several previous position (say, from index 15 to index 9).
	 * Circular, so if we reach beginning of the list, goes at the end.
	 */
	onPageUpPress() {
		this.selectedElementIndex -= this.PAGE_OFFSET;
		this.onUpArrowPress();
	},

	/**
	 * Selects a tag at several next position (say, from index 9 to index 15).
	 * Circular, so if we reach beginning of the list, goes at the beginning.
	 */
	onPageDownPress() {
		this.selectedElementIndex += this.PAGE_OFFSET;
		this.onDownArrowPress();
	},

	/**
	 * Clicks on the selected element's child if the selected element exists.
	 */
	onEnterPress() {
		if(this.selectedElement && document.contains(this.selectedElement[0])) {
			this.selectedElement.children().click();
		}
	},

	/**
	 * Removes the "selected" class from the old selected element (if it exists)
	 * and sets the "selected" class on newSelectedElement. Also deal with scrolling
	 * of the tag modal.
	 * @param {Element} index The index of the selected tag in this.elements.
	 */
	updateSelectedElement(index) {
		if(this.selectedElement) {
			this.selectedElement.removeClass(this.SELECTED_TAG_CLASS);
		}
		this.selectedElement = $(this.elements[index]);
		this.selectedElementIndex = index;
		this.selectedElement.addClass(this.SELECTED_TAG_CLASS);
		let container = $('#popover_choice_main');
		container.animate({
			scrollTop: this.selectedElement.offset().top - $('#popover_choice_main').offset().top
		}, 100);
	},

	/** 
	 * If there is at least a tag displayed, select the first of them.
	 */
	selectFirstTag() {
		if(this.elements.length > 0) {
			this.updateSelectedElement(0);
		}
	},

	/** 
	 * If there is at least a tag displayed, select the last of them.
	 */
	selectLastTag() {
		if(this.elements.length > 0) {
			this.updateSelectedElement(this.elements.length - 1);
		}
	},

	/**
	 * Selects the previous tag, or the last tag if we're at the top of the list.
	 */
	selectPreviousTag() {
		let newIndex;
		if(this.selectedElementIndex <= 0) {
			newIndex = this.elements.length - 1;
		} else {
			newIndex = this.selectedElementIndex - 1;
		}
		this.updateSelectedElement(newIndex);
	},

	/**
	 * Selects the next tag, or the first tag if we're at the bottom of the list.
	 */
	selectNextTag() {
		let newIndex;
		if(this.selectedElementIndex >= this.elements.length - 1) {
			newIndex = 0;
		} else {
			newIndex = this.selectedElementIndex + 1;
		}
		this.updateSelectedElement(newIndex);
	}
}

// Inits the keyboard tag selection's main routine.
$(document).ready(() => keyboardTagSelection.init());