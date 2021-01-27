# INSTALL Documentation for the MISP Project.

To have a more web friendly view please visit the mkdocs generated gh-pages site [here](https://misp.github.io/MISP/)

The text files in this folder are symlink to ../docs - Which is the actual source.

Currently the following install guides are being tested on a regular basis:
```
INSTALL.ubuntu1804.md
INSTALL.ubuntu2004.md
INSTALL.kali.md
INSTALL.rhel7.md
INSTALL.rhel8.md
```

Files prefixed with 'CONFIG.' are CONFIGuration guides and not full blown INSTALL guides.

UPDATE.md gives you a brief overview on how to update MISP to the latest version, as well as some other core dependencies that can be updated.

Install guides with the 'x' prefix, are marked as Experimental.

The following are tested on a semi-regular basis:
```
xINSTALL.centos7.md
xINSTALL.debian10.md
```

# INSTALL.sh hacking

First of all, please read the *INSTALL.sh* script. Running a random piece of shell script that randomly invokes sudo left right and center is dangerous. (Without a sword)

Now read *INSTALL.tpl.sh*. This is the generator for *INSTALL.sh*.

If for example you want to modify *INSTALL.sh*, NEVER EVER touch *INSTALL.sh*. This will break the checksum and I will be very, very angry.

*INSTALL.tpl.sh* will source the various Markdown files and generate the main installer. Meaning, if changes happen they mostly happen in the .md files.
The advantage being that when the manual documentation is up to date the installer is up to date.


There are 2 scenarios here.

1. There is an issue or improvement to be made in *INSTALL.ubuntu2004.md* for example.
2. A core *INSTALL.sh* issue or improvement needs to be done.

You will need *xsnippet* that extracts bits of shell code from the .md files:

```bash
mkdir -p ~/bin
git clone https://github.com/SteveClement/xsnippet.git
cd xsnippet; cp xsnippet ~/bin/
export PATH="$PATH:~/bin" # By now you are aware that this needs to be in your $PATH, aren't you. #PAAF
```

You need *rhash* too:
```bash
sudo apt install rhash
```

Now you are ready.

To test if you are really ready, do the following:

```
git clone https://github.com/MISP/MISP.git
cd MISP/INSTALL ; ./INSTALL.tpl.sh
```

The only file that should have been changed is: *INSTALL.sh.sfv*
And nothing on *stdout* should have been displayed, and the exit code would have been obviously 0.

## Scenario 1

The easiest scenario. Everythin between *# <snippet-begin* is relevant to the to be generated installer. Change to your hearts' content, run the *INSTALL.tpl.sh* script and now the following files will have changed:

```
	modified:   INSTALL.sh
	modified:   INSTALL.sh.sfv
	modified:   INSTALL.sh.sha1
	modified:   INSTALL.sh.sha256
	modified:   INSTALL.sh.sha384
	modified:   INSTALL.sh.sha512
	modified:   ../docs/INSTALL.ubuntu1804.md
```

Perfect, this looks as if it worked. This is typical, if the .md changes, the *INSTALL.sh* checksum will obviously change too. Important to note, this needs to be reflected on the *2.4* branch.
Otherwise your changes are not taken into account or something might even break if things are out of sync.

If for example you change a markdown file and the checksums have NOT changed. This means either that the changed markdown file is not yet supported by the installer. Or that you changed *INSTALL.ubuntu2004.md*
The Ubuntu 18.04 install documentation is the main Ubuntu installer file.
Ideally you merge your changed between the 18.04 and 20.04 and run the generator again.

## Scenario 2

This scenario is more complex. Have you read the *INSTALL.tpl.sh* yet? If no, please do not continue before having read it.

Good, now that you read it you noticed that there are references to the folder *docs/generic* this folder includes generic files that are shared between platforms.

For core changes, the most interesting and important files are:

- *globalVariables.md*
- *MISP_CAKE_init.md*
- *supportFunctions.md*

### globalVariables
This is the most interesting file, it will bootstrap the install environment of the MISP-Server to be.
What I always use, even for just debugging MISP issues in general:
```bash
eval "$(curl -fsSL https://raw.githubusercontent.com/MISP/MISP/2.4/docs/generic/globalVariables.md | grep -v \`\`\`)"
MISPvars
```

This will expose a standard MISP environment to my current working environment, a few important notes and potential caveats: Familiarize yourself with ":-" variables, static list:
```bash
  MISP_USER="${MISP_USER:-misp}"
  MISP_PASSWORD="${MISP_PASSWORD:-$(openssl rand -hex 32)}"
  PATH_TO_MISP="${PATH_TO_MISP:-/var/www/MISP}"
  FQDN="${FQDN:-misp.local}"
  MISP_BASEURL="${MISP_BASEURL:-""}"
  DBHOST="${DBHOST:-localhost}"
  DBNAME="${DBNAME:-misp}"
  DBUSER_ADMIN="${DBUSER_ADMIN:-root}"
  DBPASSWORD_ADMIN="${DBPASSWORD_ADMIN:-$(openssl rand -hex 32)}"
  DBUSER_MISP="${DBUSER_MISP:-misp}"
  DBPASSWORD_MISP="${DBPASSWORD_MISP:-$(openssl rand -hex 32)}"
```

Those are variables, if they are set in the current scope, via export for example, the will NOT be set with a default value.


### MISP_CAKE_init
This file includes all the cake commands to configure the MISP instance via the CLI.
As always, have you read the file?

From its' header:

```
# Core cake commands to tweak MISP and aleviate some of the configuration pains
# The $RUN_PHP is ONLY set on RHEL/CentOS installs and can thus be ignored
# This file is NOT an excuse to NOT read the settings and familiarize ourselves with them ;)
```


### supportFunctions

The list below will give you a hint what the supportFunctions do.
Reading the code will be more or less self-explanatory, plus it is documented.

For a static overview, as of 20210114 the following functions are in that file:

```
usage () {
containsElement () {
checkOpt () {
setOpt () {
command_exists () {
checkCoreOS () {
checkFlavour () {
check_forked () {
checkInstaller () {
checkManufacturer () {
space () {
progress () {
checkLocale () {
checkFail () {
ask_o () {
clean () {
checkID () {
preInstall () {
upgrade () {
checkUsrLocalSrc () {
kaliSpaceSaver () {
kaliOnTheR0ckz () {
setBaseURL () {
installRNG () {
kaliUpgrade () {
disableSleep () {
checkAptLock () {
installDepsPhp70 () {
installDepsPhp73 () {
installDeps () {
fixRedis () {
genApacheConf () {
gitPullAllRCLOCAL () {
composer () {
enableServices () {
genRCLOCAL () {
runTests () {
nuke () {
theEnd () {
```
