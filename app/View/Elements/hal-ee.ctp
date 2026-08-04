<!-- Credit: https://codepen.io/kleberbaum-the-sasster/pen/qBqzVBJ -->
<div id="hal-div-container" style="display: none;">
    <div class="loader">
        <div class="loader-bg">
            <span></span>
        </div>
        <div class="drops drops1">
            <div class="drop1"></div>
            <div class="drop2"></div>
        </div>
        <div class="drops drops2">
            <div class="drop1"></div>
            <div class="drop2"></div>
        </div>
        <div class="drops drops3">
            <div class="drop1"></div>
            <div class="drop2"></div>
        </div>
    </div>
    <svg xmlns="http://www.w3.org/2000/svg" version="1.1">
        <defs>
            <filter id="liquid">
                <feGaussianBlur in="SourceGraphic" stdDeviation="10" result="blur" />
                <feColorMatrix in="blur" mode="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 18 -7" result="liquid" />
            </filter>
        </defs>
    </svg>
</div>

<script>
    function toggleHal() {
        $('#hal-div-container').toggle()
        $('.navbar-inner').toggleClass('hal-active')
    }
</script>

<style>
    @keyframes fade-in {
        0% {
            opacity: 0;
        }

        100% {
            opacity: 1;
        }
    }

    @keyframes drop {
        0% {
            bottom: 0px;
            opacity: 1;
        }

        80% {
            opacity: 1;
        }

        90% {
            opacity: 1;
            bottom: -100px;
        }

        100% {
            opacity: 0;
            bottom: -100px;
        }
    }

    @keyframes wave {
        0% {
            background-position: 0 160px;
            background-size: 170px 300px;
        }

        100% {
            background-position: 500px -18px;
            background-size: 250px 150px;
        }
    }

    .kuhl {
        margin-top: 5px;
        width: 88%;
    }

    :root {
        --halloween-color: #ae090f;
    }

    #topBar.navbar > .navbar-inner.hal-active {
        background-color: var(--halloween-color);
        background-image: linear-gradient(to bottom, var(--halloween-color), var(--halloween-color));
        border-color: var(--halloween-color);
    }

    #topBar.navbar>.navbar-inner.navbar-inverse .brand,
    .navbar-inverse .nav>li>a {
        color: white;
    }

    .loader {
        width: 100%;
        height: 42px;
        position: absolute;
        margin: auto;
        left: 0;
        right: 0;
        top: 0;
        bottom: 0;
        text-align: center;
        line-height: 120px;
        font-family: sans-serif;
        color: #ffffff;
        font-size: 16px;
        z-index: -1;
    }

    .loader span {
        z-index: 3;
    }

    .loader-bg {
        position: absolute;
        left: 0;
        right: 0;
        top: 0;
        bottom: 0;
        z-index: 2;
        animation: wave 1s ease-out forwards;
    }

    .drops {
        -webkit-filter: url('#liquid');
        filter: url('#liquid');
        position: absolute;
        top: 0;
        left: 0;
        bottom: 0;
        right: 0;
        z-index: 1;
        opacity: 0;
        animation: fade-in .1s linear .4s forwards;
    }

    .drops1 {
        left: -44vw;
    }

    .drops2 {
        left: -70vw;
    }

    .drops3 {
        left: 70vw;
    }

    .drops1 .drop2 {
        animation-delay: 0ms;
    }

    .drops2 .drop2 {
        animation-delay: 400ms;
    }

    .drops3 .drop2 {
        animation-delay: 100ms;
    }

    .drop1,
    .drop2 {
        width: 21px;
        height: 24px;
        border-radius: 50%;
        position: absolute;
        left: 0;
        right: 0;
        bottom: 0;
        margin: auto;
        background-color: var(--halloween-color)
    }

    .drop1 {
        width: 90px;
        height: 12px;
        bottom: 2px;
        border-radius: 0;
        z-index: 0;
    }

    .drop2 {
        animation: drop 1.3s cubic-bezier(1, .19, .66, .12) .5s infinite;
    }
</style>