#### Network Interface Name salvage (optional)

This will bring back 'ethX' e.g: eth0

```bash
GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"
DEFAULT_GRUB=/etc/default/grub
for key in GRUB_CMDLINE_LINUX
do
    sudo sed -i "s/^\($key\)=.*/\1=\"$(eval echo \${$key})\"/" $DEFAULT_GRUB
done
sudo grub-mkconfig -o /boot/grub/grub.cfg
```

!!! notice
    On recent Ubuntu install Netplan is default and you need to change the Network name.
    ```
    sudo sed -i "s/enp0s3/eth0/" /etc/netplan/50-cloud-init.yaml
    ```
