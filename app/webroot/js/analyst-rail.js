(function () {
    if (window.AnalystRail) {
        return;
    }

    function markClamps(root) {
        root.querySelectorAll('.adr-card .adr-clamp:not([data-adr-checked])').forEach(function (p) {
            if (p.offsetParent === null) {
                return;
            }
            p.setAttribute('data-adr-checked', '');
            if (p.scrollHeight <= p.clientHeight + 1) {
                return;
            }
            var more = document.createElement('button');
            more.type = 'button';
            more.className = 'adr-readmore';
            more.setAttribute('aria-expanded', 'false');
            more.setAttribute('data-adr-readmore', '');
            more.textContent = more.dataset.closed = p.closest('.adr-card').dataset.adrReadMore || 'Read more';
            more.dataset.open = p.closest('.adr-card').dataset.adrReadLess || 'Read less';
            p.insertAdjacentElement('afterend', more);
        });
    }

    function toggle(button, open, labelSelector) {
        button.setAttribute('aria-expanded', String(open));
        var label = labelSelector ? button.querySelector(labelSelector) : button;
        label.textContent = open ? button.dataset.adrLabelOpen : button.dataset.adrLabel;
    }

    document.addEventListener('click', function (e) {
        var target = e.target.closest('.adr-card [data-adr-open], .adr-card [data-adr-expand], .adr-card [data-adr-replies], .adr-card [data-adr-readmore]');
        if (!target) {
            return;
        }
        var card = target.closest('.adr-card');
        if (target.hasAttribute('data-adr-open')) {
            e.preventDefault();
            openModal(target.dataset.adrOpen, target.dataset.adrSize);
        } else if (target.hasAttribute('data-adr-expand')) {
            var open = target.getAttribute('aria-expanded') !== 'true';
            card.querySelectorAll('.adr-more').forEach(function (li) { li.hidden = !open; });
            toggle(target, open, '.adr-expand-label');
            markClamps(card);
        } else if (target.hasAttribute('data-adr-replies')) {
            var list = target.nextElementSibling;
            var opened = list.hidden;
            list.hidden = !opened;
            toggle(target, opened, '.adr-replies-label');
        } else {
            var text = target.previousElementSibling;
            var expanded = text.classList.toggle('adr-clamp-open');
            target.setAttribute('aria-expanded', String(expanded));
            target.textContent = expanded ? target.dataset.open : target.dataset.closed;
        }
    });

    document.addEventListener('shown.bs.tab', function () { markClamps(document); });

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { markClamps(document); });
    } else {
        markClamps(document);
    }

    window.AnalystRail = { refresh: markClamps };
})();
