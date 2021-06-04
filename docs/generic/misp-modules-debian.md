#### Install misp-modules (optional)

```bash
# <snippet-begin 3_misp-modules.sh>
# Main MISP Modules install function
mispmodules () {
  cd /usr/local/src/
  sudo apt-get install cmake libcaca-dev liblua5.3-dev -y
  ## TODO: checkUsrLocalSrc in main doc
  if [[ ! -d /usr/local/src/misp-modules ]]; then
    debug "Cloning misp-modules"
    false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone https://github.com/MISP/misp-modules.git; done
  else
    false; while [[ $? -ne 0 ]]; do $SUDO_CMD git -C /usr/local/src/misp-modules pull; done
  fi

  # Install faup/gtcaca
  [[ ! -d "faup" ]] && false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone https://github.com/stricaud/faup.git faup; done
  [[ ! -d "gtcaca" ]] && false; while [[ $? -ne 0 ]]; do $SUDO_CMD git clone https://github.com/stricaud/gtcaca.git gtcaca; done
  sudo chown -R ${MISP_USER}:${MISP_USER} faup gtcaca
  # Install gtcaca
  cd gtcaca
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake .. && $SUDO_CMD make
  sudo make install
  cd /usr/local/src/faup
  # Install faup
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake .. && $SUDO_CMD make
  sudo make install
  sudo ldconfig

  cd /usr/local/src/misp-modules
  # some misp-modules dependencies
  sudo apt install libpq5 libjpeg-dev tesseract-ocr libpoppler-cpp-dev imagemagick libopencv-dev zbar-tools libzbar0 libzbar-dev libfuzzy-dev -y
  # If you build an egg, the user you build it as need write permissions in the CWD
  sudo chgrp $WWW_USER .
  sudo chmod og+w .
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install -I -r REQUIREMENTS
  sudo chgrp staff .
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install -I .
  $SUDO_WWW ${PATH_TO_MISP}/venv/bin/pip install censys pyfaup

  # Start misp-modules as a service
  sudo cp /usr/local/src/misp-modules/etc/systemd/system/misp-modules.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now misp-modules

  # Sleep 9 seconds to give misp-modules a chance to spawn
  sleep 9
}
# <snippet-end 3_misp-modules.sh>
```
