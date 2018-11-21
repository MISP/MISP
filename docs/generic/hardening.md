# Hardening a base system

## Intro

MISP is a web-based **information sharing platform**, by design it is kept rather simple and hardening can be done by following the common best practices.

Bare in mind that neither the MISP documentation efforts or the core MISP project can give you the ultimate guide on how to harden your system.
This is not the purpose of the MISP Project but the purpose and care of those individuals and organizations deploying MISP Instances.

Nevertheless here is a very rough **food for thoughts** bulletpoint list for you to consider, and a list of some hardening ressources below.

- Are we using SSL by default? (Especially when syncing over the internet and exposing the API)
- How to we access the machine remotely? Via ssh? What is the path to get there? Does a [bastion host](https://en.wikipedia.org/wiki/Bastion_host) make sense?
- Is the machine shared with other user accounts? Do I need to care about useri-land security due to this sharing?
- Is the instance deployed in the "**cloud**"? Is it a VPS? AWS? docker? ansible? kubernetes? whateverCloudContainterMagicIsFancibleNow?
- Do we need to encrypt the partitions where some data is stored?
- Are we redundant in case one MISP instance might fail?
- Is the database server and any other servers running on the machine bound to **localhost**? Do we need to expose because our setup is more complex?
- Do we have enough storage? What about [MISP and size estimation](https://misp-project.org/MISP-sizer/) anyways?
- Do we care about BIOS updates?
- Do we care about physical access to the servers? (Disabling USB ports etc...)
- Is any fancy management engine à la [IME](https://en.wikipedia.org/wiki/Intel_Management_Engine) in use?

## Resources

[Debian Wiki Hardening](https://wiki.debian.org/Hardening)
