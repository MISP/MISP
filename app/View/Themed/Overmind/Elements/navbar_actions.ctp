<?php // The navbar entries' actions, shared by navbar.ctp and navbar_rail.ctp. ?>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        const themeButtons = document.querySelectorAll('.setTheme');

        themeButtons.forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();

                const theme = String(this.dataset.theme || '');
                const safeTheme = encodeURIComponent(theme);

                fetch('<?php echo $baseurl; ?>/user_settings/setTheme/' + safeTheme, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'X-CSRF-Token': (window.csrfToken || '')
                    },
                    credentials: 'same-origin'
                })
                .then(response => {
                    if (response.ok) {
                        location.reload();
                        throw new ShowToast('<?php echo __('Theme updated!'); ?>');
                    } else {
                        throw new Error('Server Error');
                    }
                })
                .catch(error => {
                    alert('<?php echo __('Failed to toggle Beta UI. Please try again.'); ?>');
                });
            });
        });

        document.querySelectorAll('.set-bootstrap-theme').forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                if (this.getAttribute('aria-current') === 'true') {
                    return;
                }
                const theme = encodeURIComponent(String(this.dataset.theme || ''));
                fetch('<?= $baseurl ?>/user_settings/setBootstrapTheme/' + theme, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'X-CSRF-Token': (window.csrfToken || '')
                    },
                    credentials: 'same-origin'
                })
                .then(response => {
                    if (!response.ok) throw new Error('Server Error');
                    location.reload();
                })
                .catch(() => {
                    showToast(<?= json_encode(__('Failed to change the theme. Please try again.')) ?>, 'danger');
                });
            });
        });

        document.querySelectorAll('.toggle-dark-mode').forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                toggleDarkMode();
            });
        });

        document.querySelectorAll('.set-homepage').forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();

                fetch('<?php echo $baseurl; ?>/user_settings/setHomePage', {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': (window.csrfToken || '')
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ path: window.location.pathname })
                })
                .then(response => {
                    if (!response.ok) throw new Error('Server Error');
                    showToast('<?php echo __('Homepage saved!'); ?>');
                })
                .catch(() => {
                    showToast('<?php echo __('Failed to set homepage. Please try again.'); ?>', 'danger');
                });
            });
        });

        initThemeEasterEgg();
    });

    /*
     * Hidden themes: applying every visible theme within TOUR_WINDOW shows a
     * riddle, unseen ones first; flipping dark mode FLIPS times within FLIP_WINDOW unmasks them.
     */
    function initThemeEasterEgg() {
        const secrets = document.querySelectorAll('.theme-secret');
        if (!secrets.length) {
            return;
        }
        const TOUR_KEY = 'mispThemeTour';
        const TOUR_WINDOW = 120000;
        const FLIPS = 10;
        const FLIP_WINDOW = 5000;
        const hints = <?= json_encode([
            __("You've seen every side of this place… but only one side at a time. Some secrets need both, over and over."),
            __('The light side shows you everything. The dark side shows you the rest. Go back and forth until they agree.'),
            __("The menu doesn't lie, it just doesn't tell you everything. Ask it again from the other side. And again."),
            __('1010101010. Say it where light and dark take turns.'),
            __("Sunrise, sunset. Five of each, without a breath between, and see who's still awake."),
            __('Flick. Flick. Flick… ten in one breath, and the hidden ones come out.'),
            __("The night shift and the starship crew never clock in by daylight. Keep turning the lights off and on, and they'll come."),
            __('The foundry runs cold and the bridge is dark. Both are waiting for someone to work the lights.'),
            __("Steel and stars don't do daylight. Keep the sun guessing and they'll turn up."),
            __("Can't decide between light and dark? Some themes reward exactly that."),
            __('Is that all of them? Ask the ones with two faces. Ask them again. And again.'),
            __('Light. Dark. Light. Dark. …Still there? Keep going.'),
        ], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG) ?>;
        const teaser = <?= json_encode(
            __('Still stuck? Tour the themes once more, each lap whispers something new.'),
            JSON_UNESCAPED_UNICODE | JSON_HEX_TAG
        ) ?>;
        const SEEN_KEY = 'mispThemeHintsSeen';

        const visible = Array.from(new Set(Array.from(
            document.querySelectorAll('.set-bootstrap-theme:not(.is-secret)'),
            button => button.dataset.theme
        ).filter(Boolean)));
        const current = document.documentElement.dataset.mispTheme;
        if (visible.includes(current)) {
            const now = Date.now();
            let tour = {};
            try {
                tour = JSON.parse(localStorage.getItem(TOUR_KEY)) || {};
            } catch (e) {}
            tour[current] = now;
            Object.keys(tour).forEach(function(theme) {
                if (!visible.includes(theme) || now - tour[theme] > TOUR_WINDOW) {
                    delete tour[theme];
                }
            });
            const complete = visible.every(theme => theme in tour);
            try {
                if (complete) {
                    localStorage.removeItem(TOUR_KEY);
                } else {
                    localStorage.setItem(TOUR_KEY, JSON.stringify(tour));
                }
            } catch (e) {}
            if (complete && typeof showToast === 'function') {
                let seen = [];
                try {
                    seen = JSON.parse(localStorage.getItem(SEEN_KEY)) || [];
                } catch (e) {}
                if (!Array.isArray(seen)) {
                    seen = [];
                }
                let pool = hints.map((hint, i) => i).filter(i => !seen.includes(i));
                if (!pool.length) {
                    seen = [];
                    pool = hints.map((hint, i) => i);
                }
                const pick = pool[Math.floor(Math.random() * pool.length)];
                seen.push(pick);
                try {
                    localStorage.setItem(SEEN_KEY, JSON.stringify(seen));
                } catch (e) {}
                showToast(hints[pick] + ' ' + teaser, 'dark', 15000);
            }
        }

        let flips = [];
        document.querySelectorAll('.toggle-dark-mode').forEach(function(button) {
            button.addEventListener('click', function() {
                const now = Date.now();
                flips = flips.filter(time => now - time < FLIP_WINDOW);
                flips.push(now);
                if (flips.length >= FLIPS) {
                    flips = [];
                    secrets.forEach(function(item) {
                        item.hidden = false;
                    });
                }
            });
        });
    }
</script>