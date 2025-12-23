(function () {
    function init() {
        const container = document.querySelector('.misp-fireworks');
        if (!container) return;

        function burst() {
            const x = Math.random() * window.innerWidth;
            const y = 15 + Math.random() * 30;
            const hue = Math.floor(Math.random() * 360);
            const count = 14 + Math.floor(Math.random() * 6);

            for (let i = 0; i < count; i++) {
                const p = document.createElement('div');
                const angle = Math.random() * Math.PI * 2;
                const distance = 30 + Math.random() * 35;

                p.className = 'misp-firework-particle';
                p.style.left = x + 'px';
                p.style.top = y + 'px';
                p.style.setProperty('--dx', Math.cos(angle) * distance + 'px');
                p.style.setProperty('--dy', Math.sin(angle) * distance + 'px');
                p.style.setProperty('--hue', hue);

                container.appendChild(p);
                setTimeout(() => p.remove(), 1300);
            }
        }

        setInterval(() => {
            burst();
            if (Math.random() > 0.35) setTimeout(burst, 500);
        }, 2200);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
