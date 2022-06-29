#### Network Interface Name salvage (optional)

This will bring back 'ethX' e.g: eth0

```bash
# <snippet-end interfaces.sh>
GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"
DEFAULT_GRUB=/etc/default/grub

echo "--- Using old style name (ethX) for interfaces"
#for key in GRUB_CMDLINE_LINUX
#do
#    sudo sed -i "s/^\($key\)=.*/\1=\"$(eval echo \${$key})\"/" $DEFAULT_GRUB
#done
sed  -r  's/^(GRUB_CMDLINE_LINUX=).*/\1\"net\.ifnames=0\ biosdevname=0\"/' /etc/default/grub | sudo tee /etc/default/grub > /dev/null

# install ifupdown since ubuntu 18.04
sudo apt-get update
sudo apt-get install -y ifupdown

# enable eth0
echo "--- Configuring eth0"

echo "# The primary network interface
auto eth0
iface eth0 inet dhcp" | sudo tee /etc/network/interfaces
sudo grub-mkconfig -o /boot/grub/grub.cfg
sudo update-grub  > /dev/null 2>&1
# <snippet-end interfaces.sh>
```

!!! notice
    On recent Ubuntu install Netplan is default and you might need to change the Network name in its respective config file.
    ```
    sudo sed -i "s/enp0s3/eth0/" /etc/netplan/50-cloud-init.yaml
    ```
    OR on Ubuntu 19.04 (yay for changing this every 5 commits... #n00bs)
    ```
    sudo sed -i "s/enp0s3/eth0/" /etc/netplan/01-netcfg.yaml
    ```
    OR on Ubuntu 22.04
    ```
    sudo sed -i "s/enp0s3/eth0/" /etc/netplan/00-installer-config.yaml
    ```
