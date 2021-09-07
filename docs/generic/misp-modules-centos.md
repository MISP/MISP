## 9.07/ misp-modules

```bash
# <snippet-begin 3_misp-modules_RHEL.sh>
mispmodulesRHEL () {
  # some misp-modules dependencies for RHEL<8
  [[ "${DIST_VER}" =~ ^[7].* ]] && sudo dnf install openjpeg-devel gcc-c++ poppler-cpp-devel pkgconfig python3-devel redhat-rpm-config -y

  # some misp-modules dependencies for RHEL8
  ([[ "${DISTRI}" == "fedora33" ]] || [[ "${DISTRI}" == "fedora34" ]] || [[ "${DIST_VER}" =~ ^[8].* ]]) && sudo dnf install openjpeg2-devel gcc-c++ poppler-cpp-devel pkgconfig python3-devel redhat-rpm-config -y

  sudo chmod 2777 /usr/local/src
  sudo chown root:users /usr/local/src
  cd /usr/local/src/
  false; while [[ $? -ne 0 ]]; do ${SUDO_WWW} git clone https://github.com/MISP/misp-modules.git; done
  cd misp-modules
  # pip install
  ${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install -U -I -r REQUIREMENTS
  ${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install -U .
  ${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/pip install pyfaup censys
  # some misp-modules dependencies for RHEL<8
  ([[ "${DISTRI}" == "fedora33" ]] || [[ "${DIST_VER}" =~ ^[7].* ]]) && sudo dnf install rubygem-rouge rubygem-asciidoctor zbar-devel opencv-devel -y
  # some misp-modules dependencies for RHEL8
  [[ "${DIST_VER}" =~ ^[8].* ]] && sudo dnf install https://packages.endpoint.com/rhel/8/main/x86_64/endpoint-repo-8-1.ep8.noarch.rpm -y && sudo dnf install zbar-devel opencv-devel -y

  echo "[Unit]
  Description=MISP modules
  After=misp-workers.service

  [Service]
  Type=simple
  User=${WWW_USER}
  Group=${WWW_USER}
  WorkingDirectory=/usr/local/src/misp-modules
  Environment="PATH=/var/www/MISP/venv/bin"
  ExecStart=\"${PATH_TO_MISP}/venv/bin/misp-modules -l 127.0.0.1 -s\"
  Restart=always
  RestartSec=10

  [Install]
  WantedBy=multi-user.target" |sudo tee /etc/systemd/system/misp-modules.service

  sudo systemctl daemon-reload
  # Test misp-modules
  ${SUDO_WWW} ${PATH_TO_MISP}/venv/bin/misp-modules -l 127.0.0.1 -s &
  sudo systemctl enable --now misp-modules
}
# <snippet-end 3_misp-modules_RHEL.sh>
```

