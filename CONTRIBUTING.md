
# Contributing to MISP Project

MISP project is a large free software project composed of multiple sub-projects which are contributed by different contributors who are generally active users of the MISP project. MISP project fully supports the [Contributor Covenant Code of Conduct](https://github.com/MISP/MISP/blob/2.4/code_of_conduct.md) to foster an open and dynamic environment for contributing and the exchange in the threat intelligence and information exchange field.

The MISP roadmap is mostly based on the user communities (e.g. private communities, CSIRTs communities, security researchers, ISACs - Information Sharing and Analysis Center, security providers, governmental or military organisations) relying on MISP to perform their duties of information sharing and analysis. If you see an existing issue which covers your needs, don't hesitate to comment on it.

Participating in the MISP project is easy and everyone can contribute following their own ability:

## Reporting a bug or an issue, suggesting features

Reporting a bug or an issue, suggesting a new feature in the [MISP core](https://github.com/MISP/MISP/issues), [misp-modules](https://github.com/MISP/misp-modules/issues), [misp-book](https://github.com/MISP/misp-book/issues), [misp-taxonomies](https://github.com/MISP/misp-taxonomies/issues), [misp-galaxy](https://github.com/MISP/misp-galaxy/issues) or any of the projects within the [MISP project org](https://github.com/MISP/). When reporting an issue on GitHub, use one of the [issue templates](https://github.com/MISP/MISP/issues/new/choose). Don't hesitate to add as much information as you can, including the version of MISP which you are running, screen-shots with annotation, suggested features and steps on how to reproduce an issue. To disclose a security issue confidentially, please see the [Reporting security vulnerabilities](#reporting-security-vulnerabilities) page.

Before opening a new issue, search both open and closed issues to avoid duplicate issues. For example, you may be experiencing a bug that was just fixed, in which case the report for that bug is probably closed. Here, it would be useful to view all bug reports, both open and closed, with the most recently updated sorted to the top. If you find an issue that seems to be similar to yours, read through it. If you find an issue that is the same as or subsumes yours, leave a comment on the existing issue rather than filing a new one, even if the existing issue is closed. The MISP team will see your comment and reopen the issue, if appropriate. For example, you can leave a comment with additional information to help the maintainer debug it. Adding a comment will subscribe you to email notifications, which can be helpful in getting important updates regarding the issue. If you don’t have anything to add but still want to receive email updates, you can click the “Subscribe” button at the side or bottom of the comments. Commenting on existing issues is an indicator for us regarding the priority of certain features and how important these are to the users.

Creating a new issue is simply a way for you to submit an item for the MISP team’s consideration. It is up to the MISP team to decide whether or how to address your issue, which may include closing the issue without taking any action on it. Even if your issue is kept open, however, you should not expect it to be addressed within any particular time frame, or at all. At the time of this writing, there are well over 1.7 thousand open issues in the main MISP repo alone, not considering the other related repos. The MISP team has its own [roadmap]() and priorities, which will govern the manner and order in which open issues are addressed.

### Following up afterward

If the MISP developers make a code change that resolves your issue, then your GitHub issue will typically be closed from the relevant patch message. There is one main branch, `2.4` (current stable version), that we consider as stable with frequent updates as hot-fixes. Features are developed in separated branches and then regularly merged into the 2.4 stable branch. If you so choose, you can test the fix while it’s in the feature branch, or you can wait for it to land in the stable repository. If, after testing the fix, you find that it does not really fix your bug, please leave a comment on your issue explaining the situation. When you do, we will receive a notification and respond on your issue or reopen it (or both). Please do not create a duplicate issue.

In other cases, your issue may be closed with a specific resolution, such as R: invalid, R: duplicate, or R: wontfix. Each of these labels has a description that explains the label. We’ll also leave a comment explaining why we’re closing the issue with one of these specific resolutions. If the issue is closed without one of these specific resolutions or a comment, then it means, by default, that your reported bug was fixed or your requested enhancement was implemented.

## Reporting security vulnerabilities

View our [Security Policy](https://github.com/MISP/MISP/security/policy).
 
## Contributing to MISP core

### Git workflow

If you want to contribute to the [MISP core](https://github.com/MISP/MISP) project:

- First fork the [MISP core project](https://github.com/MISP/MISP)
- Branch off from 2.4 (2.4 branch is the main branch of development in MISP) `git checkout 2.4`
- Then create a branch for your own contribution (bug fixes, enhancement, new features) by typing `git checkout -b fix-glossy-user-interface`
- Work on your fix or feature (only work on that, avoid committing any debug functionalities, testing or unused code)
- Commit your fix or feature (and sign it with GnuPG - if you have a GnuPG key) with a meaningful commit message as recommended in our [Commit Messages Best Practices](https://github.com/MISP/MISP/wiki/CommitMessageBestPractices). MISP uses [gitchangelog](https://github.com/vaab/gitchangelog/blob/master/src/gitchangelog/gitchangelog.rc.reference) to generate changelog, so it's recommended that when writing commit messages, use `new:` for new features, `fix:` when it's a bug-fix or `chg` when it's re-factoring or clean-up..
- Push and then [open a pull-request](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request) via the GitHub interface.

For changes in categories and types see the [Categories & Types Changes CheckList](https://github.com/MISP/MISP/wiki/Categories-&-Types-changes-CheckList).

If you have never done a pull-request, there is [The beginner's guide to contributing to a GitHub project](https://akrabat.com/the-beginners-guide-to-contributing-to-a-github-project/)

Some recommendations to get your PR merged quickly:

- Small gradual changes are preferred over big and complex changes.
- If the changes require some documentation changes, a pull-request on [misp-book](https://github.com/MISP/misp-book) is strongly recommended.
- If the commit message contain all the information regarding the changes, it's easier for the maintainer to do the review.
- Avoid committing sensitive information, debugging code or unrelated code in the PR.

### Translating MISP

Thank you for your interest in making MISP easier to use in your own language!

We accept translations on Crowdin: https://crowdin.com/project/misp. MISP is currently available in __ languages. You can help us bring more languages. Crowdin is a localization management platform that helps companies to translate their software. Note that CrowdIn is inpendent from MISP and they have their own [privacy policy](https://support.crowdin.com/privacy-policy/). 

You can help correct, improve, or complete the translations of MISP programs into your native language. MISP can be translated into more than 140 languages this way. Most of MISP can be translated directly online, through a simple web interface, after logging in with CrowdIn. In order to get started with using CrowdIn, you can [read their introductory article](https://support.crowdin.com/for-volunteer-translators/). Note that only reviewed translations are included in MISP.

If you want to go further, you can help translate the MISP website or MISP Book. 

### For native English speakers

Most of MISP developers are not native English speakers so you are more than welcome to correct or improve our English. For this, you can either follow the [Git workflow]() or propose on [Gitter](https://gitter.im/MISP/MISP) another way that suits you better to share your improvements with us.

## Contributing to other MISP Projects

### MISP taxonomies

If you cannot find an existing taxonomy fitting your needs, you can extend an existing one (especially the ones originated from the MISP project) or create a new one.

Create a JSON file describing your taxonomy as triple tags (e.g. check an existing one such as the [Admiralty Scale](https://github.com/MISP/misp-taxonomies/tree/master/admiralty-scale)) taxonomy, create a directory matching your name space, put your machinetag file in the directory and create a pull request. That's it. Everyone can benefit from your taxonomy and it can be automatically enabled in information sharing tools such as [MISP](https://www.github.com/MISP/MISP).

We strongly recommend to validate the JSON file using [jq](https://github.com/MISP/misp-taxonomies/blob/master/jq_all_the_things.sh) before doing a pull-request. We also strongly recommend to run [the validator](https://github.com/MISP/misp-taxonomies/blob/master/validate_all.sh) to check if the JSON validates the schema.

For more information, see the presentation slides on "[Information Sharing and Taxonomies Practical Classification of Threat Indicators using MISP](https://www.circl.lu/assets/files/misp-training/3.2-MISP-Taxonomy-Tagging.pdf)" given at the last MISP training in Luxembourg.

### MISP galaxy

In the world of threat intelligence, there are many different models or approaches to order, classify or describe threat actors, threats or activity groups. We welcome new ways of describing threat intelligence as the galaxy model allows to reuse the ones you use or trust for your organization or community.

Fork the project, update or create a galaxy or clusters and make a pull-request.

We strongly recommend to validate the JSON file using [jq](https://github.com/MISP/misp-galaxy/blob/master/jq_all_the_things.sh) before doing a pull-request. We also strongly recommend to run [the validator](https://github.com/MISP/misp-galaxy/blob/master/validate_all.sh) to check if the JSON validates the schema.

### Building software compatible with MISP formats and improving MISP formats

[MISP formats](https://github.com/MISP/misp-rfc) are open and free standards. We invite software developers to use the native MISP format for exchanging threat intelligence and support information sharing/analysis. The MISP formats are simple JSON formats implemented in various software including the MISP core application along with various libraries such as [PyMISP](https://github.com/MISP/PyMISP).

If you want to contribute to the MISP formats (which are actively based on the MISP core implementation), feel free to open an issue at [misp-rfc](https://github.com/MISP/misp-rfc).
  

