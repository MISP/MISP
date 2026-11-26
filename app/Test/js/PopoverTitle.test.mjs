// openPopover (misp.js) passes html: true for the popover's content, so
// Bootstrap 2 renders the title as HTML as well, and openPopover renders it
// again once shown. The title comes from the trigger's title attribute,
// which the browser hands back decoded: it is text both times.
//
// Run with:
//   node --test app/Test/js/PopoverTitle.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { lines, run } from './browserScript.mjs';

const TITLE = 'x<i>y</i>';

function page() {
    const titleHtml = [];
    const titleNode = { html(value) { titleHtml.push(value); return this; } };
    const tip = {
        on() { return this; },
        offset: () => ({ top: 100 }),
        css() { return this; },
        find: selector => (selector === 'h3.popover-title' ? titleNode : null),
    };

    // Bootstrap 2.3's popover, as far as openPopover uses it.
    function bootstrapPopover(element, options) {
        if (element.attrs.title || typeof element.attrs['data-original-title'] !== 'string') {
            element.attrs['data-original-title'] = element.attrs.title || '';
            element.attrs.title = '';
        }
        return {
            options: { ...options },
            tip: () => tip,
            getTitle() {
                return element.attrs['data-original-title']
                    || (typeof this.options.title === 'function' ? this.options.title.call(element) : this.options.title);
            },
            setContent() {
                titleNode.html(this.getTitle());
            },
        };
    }

    function $(element) {
        return {
            attr(name, value) {
                if (value === undefined) return element.attrs[name];
                element.attrs[name] = value;
                return this;
            },
            data: key => element.data[key],
            addClass() { return this; },
            on(event, handler) { element.handlers[event] = handler; return this; },
            popover(option) {
                if (typeof option === 'object') {
                    element.data.popover = bootstrapPopover(element, option);
                } else if (option === 'show') {
                    element.data.popover.setContent();
                    element.handlers['shown.bs.popover'].call(element);
                }
                return this;
            },
        };
    }

    const context = run([
        lines('misp.js', 'function escapeHtml(', '}'),
        lines('misp.js', 'function openPopover(', '}'),
    ].join('\n'), { $ });
    return { openPopover: context.openPopover, titleHtml };
}

test('a title with markup is shown as text', () => {
    const { openPopover, titleHtml } = page();
    const trigger = { attrs: { title: TITLE }, data: {}, handlers: {} };

    openPopover(trigger, '<p>content</p>');

    assert.ok(titleHtml.length >= 2, 'Bootstrap and openPopover both render the title');
    for (const html of titleHtml) {
        assert.ok(html.startsWith('x&lt;i&gt;y&lt;/i&gt;'), html);
    }
});

test('an empty title still gets the spacer and the close button', () => {
    const { openPopover, titleHtml } = page();
    const trigger = { attrs: { title: '' }, data: {}, handlers: {} };

    openPopover(trigger, '<p>content</p>');

    assert.ok(titleHtml.includes('&nbsp;<button class="close" style="margin-left: 5px;">×</button>'));
});
