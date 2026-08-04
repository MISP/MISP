// Menu Button (WAI-ARIA pattern). Hydrates any element marked with
// [data-misp-menubutton] that contains a [data-misp-menubutton-
// trigger] button and a [data-misp-menubutton-menu] panel with
// role="menu" and child elements with role="menuitem".
//
// Keyboard contract:
//   Trigger
//     Enter / Space / ArrowDown   open menu, focus first item
//     ArrowUp                     open menu, focus last item
//   Menu items
//     ArrowDown / ArrowUp         cycle to next / previous item
//     Home / End                  jump to first / last item
//     Escape                      close menu, return focus to trigger
//     Tab / Shift+Tab             close menu, focus moves on naturally
//     Space                       activate focused item (Enter on an
//                                 anchor activates via the browser)
//
// Mouse contract:
//   Click trigger                 toggle open/closed
//   Click outside                 close
//   Click item                    native activation (e.g. anchor nav)
//
// The module is idempotent — calling initMenuButtons twice on the
// same root is a no-op (a `__mispMenuButton` marker is stashed on
// the root element).

const ATTR_ROOT    = 'data-misp-menubutton';
const ATTR_TRIGGER = 'data-misp-menubutton-trigger';
const ATTR_MENU    = 'data-misp-menubutton-menu';

class MenuButton {
    constructor(rootEl) {
        this.root    = rootEl;
        this.trigger = rootEl.querySelector(`[${ATTR_TRIGGER}]`);
        this.menu    = rootEl.querySelector(`[${ATTR_MENU}]`);
        if (!this.trigger || !this.menu) return;
        this._onDocClick   = this._onDocClick.bind(this);
        this._onDocKeydown = this._onDocKeydown.bind(this);
        this._wire();
    }

    items() {
        return [...this.menu.querySelectorAll('[role="menuitem"]')];
    }

    isOpen() {
        return this.trigger.getAttribute('aria-expanded') === 'true';
    }

    open(focusIndex = 0) {
        if (this.isOpen()) return;
        this.menu.hidden = false;
        this.menu.classList.add('is-open');
        this.trigger.setAttribute('aria-expanded', 'true');
        const its = this.items();
        if (its.length) {
            const idx = focusIndex === -1 ? its.length - 1 : focusIndex;
            its[idx].focus();
        }
        // Defer doc listeners by a tick so the *opening* click event
        // doesn't immediately trigger _onDocClick → close.
        setTimeout(() => {
            this.root.ownerDocument.addEventListener('click', this._onDocClick);
            this.root.ownerDocument.addEventListener('keydown', this._onDocKeydown);
        }, 0);
    }

    close({ restoreFocus = true } = {}) {
        if (!this.isOpen()) return;
        this.menu.classList.remove('is-open');
        this.menu.hidden = true;
        this.trigger.setAttribute('aria-expanded', 'false');
        this.root.ownerDocument.removeEventListener('click', this._onDocClick);
        this.root.ownerDocument.removeEventListener('keydown', this._onDocKeydown);
        if (restoreFocus) this.trigger.focus();
    }

    toggle() {
        if (this.isOpen()) this.close({ restoreFocus: false });
        else this.open(0);
    }

    _wire() {
        this.trigger.addEventListener('click', (e) => {
            e.preventDefault();
            this.toggle();
        });

        this.trigger.addEventListener('keydown', (e) => {
            switch (e.key) {
                case 'ArrowDown':
                case 'Down':
                    e.preventDefault();
                    this.open(0);
                    break;
                case 'ArrowUp':
                case 'Up':
                    e.preventDefault();
                    this.open(-1);
                    break;
                case 'Enter':
                case ' ':
                case 'Spacebar':
                    e.preventDefault();
                    this.open(0);
                    break;
            }
        });

        this.menu.addEventListener('keydown', (e) => {
            const its = this.items();
            if (!its.length) return;
            const idx = its.indexOf(this.root.ownerDocument.activeElement);
            switch (e.key) {
                case 'ArrowDown':
                case 'Down': {
                    e.preventDefault();
                    const next = its[(idx + 1) % its.length];
                    next.focus();
                    break;
                }
                case 'ArrowUp':
                case 'Up': {
                    e.preventDefault();
                    const prev = its[(idx - 1 + its.length) % its.length];
                    prev.focus();
                    break;
                }
                case 'Home':
                    e.preventDefault();
                    its[0].focus();
                    break;
                case 'End':
                    e.preventDefault();
                    its[its.length - 1].focus();
                    break;
                case 'Escape':
                case 'Esc':
                    e.preventDefault();
                    this.close();
                    break;
                case 'Tab':
                    // Let browser move focus naturally; just dismiss
                    // the menu so it doesn't stay open underneath.
                    this.close({ restoreFocus: false });
                    break;
                case ' ':
                case 'Spacebar': {
                    // Anchors don't activate on Space natively. Forward
                    // it to a click so the menuitem fires consistently.
                    const active = this.root.ownerDocument.activeElement;
                    if (active && this.menu.contains(active)) {
                        e.preventDefault();
                        active.click();
                    }
                    break;
                }
            }
        });
    }

    _onDocClick(e) {
        if (this.root.contains(e.target)) return;
        this.close({ restoreFocus: false });
    }

    _onDocKeydown(e) {
        if (e.key === 'Escape' || e.key === 'Esc') {
            e.preventDefault();
            this.close();
        }
    }
}

export function initMenuButtons(scope) {
    const root = scope || document;
    const els = root.querySelectorAll(`[${ATTR_ROOT}]`);
    for (const el of els) {
        if (el.__mispMenuButton) continue;
        el.__mispMenuButton = new MenuButton(el);
    }
}
