# JS DEV

Hey there friend

If you're wanting to go develop javascript, we use a few node packages for
compatibility with people that might use older browsers and such.

## Installation (ubuntu 16)

```bash
sudo apt-get install nodejs
cd /var/www/MISP/app/webroot/js
sudo -u www-data npm i
npm run build
```

This will compile the JS into old-style code.

## Development

```bash
npm run watch
```

This will start watching your es6 file for changes, and will compile on the fly

## Production

Just before you commit your changes, run

```bash
npm run prod
```

This will make a minified JS for quick and easy loading! Yay!
