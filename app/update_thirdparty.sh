#!/usr/bin/env bash

set -e

D3JS='3.5.17'
JQUERY_UI='1.11.4'
JQUERY='2.2.4'
BOOTSTRAP_COLORPICKER='2.0.0'  # Anything higher supports transparent color and requires changes in MISP code
BOOTSTRAP_DATEPICKER='1.5.1'  # Need to try 1.6.X
BOOTSTRAP_TIMEPICKER='0.3.0'  # Latest version working with Bootstrap 2.X
BOOTSTRAP_TRANSITION='2.3.2'  # Latest 2.X bootstrap
CAL_HEATMAP='3.6.0'


TMP_DIR='temp/'

rm -rf ${TMP_DIR}
mkdir ${TMP_DIR}
wget https://github.com/d3/d3/releases/download/v${D3JS}/d3.zip -O ${TMP_DIR}/d3.zip
wget http://jqueryui.com/resources/download/jquery-ui-${JQUERY_UI}.zip -O ${TMP_DIR}/jquery-ui.zip
wget https://github.com/jdewit/bootstrap-timepicker/releases/download/v${BOOTSTRAP_TIMEPICKER}/bootstrap-timepicker.zip -O ${TMP_DIR}/bootstrap-timepicker.zip
wget http://getbootstrap.com/${BOOTSTRAP_TRANSITION}/assets/bootstrap.zip -O ${TMP_DIR}/bootstrap.zip
wget https://github.com/wa0x6e/cal-heatmap/archive/${CAL_HEATMAP}.zip -O ${TMP_DIR}/cal_heatmap.zip

wget https://code.jquery.com/jquery-${JQUERY}.js -O webroot/js/jquery.js

wget https://cdnjs.cloudflare.com/ajax/libs/bootstrap-colorpicker/${BOOTSTRAP_COLORPICKER}/js/bootstrap-colorpicker.js -O webroot/js/bootstrap-colorpicker.js
wget https://cdnjs.cloudflare.com/ajax/libs/bootstrap-colorpicker/${BOOTSTRAP_COLORPICKER}/css/bootstrap-colorpicker.css -O webroot/css/bootstrap-colorpicker.css
wget https://cdnjs.cloudflare.com/ajax/libs/bootstrap-colorpicker/${BOOTSTRAP_COLORPICKER}/img/bootstrap-colorpicker/alpha-horizontal.png -O webroot/img/bootstrap-colorpicker/alpha-horizontal.png
wget https://cdnjs.cloudflare.com/ajax/libs/bootstrap-colorpicker/${BOOTSTRAP_COLORPICKER}/img/bootstrap-colorpicker/alpha.png -O webroot/img/bootstrap-colorpicker/alpha.png
wget https://cdnjs.cloudflare.com/ajax/libs/bootstrap-colorpicker/${BOOTSTRAP_COLORPICKER}/img/bootstrap-colorpicker/hue-horizontal.png -O webroot/img/bootstrap-colorpicker/hue-horizontal.png
wget https://cdnjs.cloudflare.com/ajax/libs/bootstrap-colorpicker/${BOOTSTRAP_COLORPICKER}/img/bootstrap-colorpicker/hue.png -O webroot/img/bootstrap-colorpicker/hue.png
wget https://cdnjs.cloudflare.com/ajax/libs/bootstrap-colorpicker/${BOOTSTRAP_COLORPICKER}/img/bootstrap-colorpicker/saturation.png -O webroot/img/bootstrap-colorpicker/saturation.png

wget https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/${BOOTSTRAP_DATEPICKER}/js/bootstrap-datepicker.js -O webroot/js/bootstrap-datepicker.js
wget https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/${BOOTSTRAP_DATEPICKER}/css/bootstrap-datepicker.css -O webroot/css/bootstrap-datepicker.css

unzip -o ${TMP_DIR}/d3.zip -d ${TMP_DIR}
mv -f ${TMP_DIR}/d3.js webroot/js/d3.js

unzip -o ${TMP_DIR}/jquery-ui.zip -d ${TMP_DIR}
mv -f ${TMP_DIR}/jquery-ui-${JQUERY_UI}/jquery-ui.js webroot/js/jquery-ui.js
mv -f ${TMP_DIR}/jquery-ui-${JQUERY_UI}/jquery-ui.css webroot/css/jquery-ui.css

unzip -o ${TMP_DIR}/bootstrap-timepicker.zip -d ${TMP_DIR}
mv -f ${TMP_DIR}/bootstrap-timepicker/js/bootstrap-timepicker.js webroot/js/bootstrap-timepicker.js
mv -f ${TMP_DIR}/bootstrap-timepicker/css/bootstrap-timepicker.css webroot/css/bootstrap-timepicker.css

unzip -o ${TMP_DIR}/bootstrap.zip -d ${TMP_DIR}
mv -f ${TMP_DIR}/bootstrap/js/bootstrap.js webroot/js/bootstrap.js
mv -f ${TMP_DIR}/bootstrap/css/bootstrap.css webroot/css/bootstrap.css
mv -f ${TMP_DIR}/bootstrap/img/glyphicons-halflings-white.png webroot/img/glyphicons-halflings-white.png
mv -f ${TMP_DIR}/bootstrap/img/glyphicons-halflings.png webroot/img/glyphicons-halflings.png

unzip -o ${TMP_DIR}/cal_heatmap.zip -d ${TMP_DIR}
mv -f ${TMP_DIR}/cal-heatmap-${CAL_HEATMAP}/cal-heatmap.js webroot/js/cal-heatmap.js
mv -f ${TMP_DIR}/cal-heatmap-${CAL_HEATMAP}/cal-heatmap.css webroot/css/cal-heatmap.css


rm -rf ${TMP_DIR}
