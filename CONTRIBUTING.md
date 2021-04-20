# Contributing to MISP Project

MISP project is a large free software project composed of multiple sub-projects which are contributed by different contributors who are generally active users of the MISP project. MISP project fully supports the [Contributor Covenant Code of Conduct](https://github.com/MISP/MISP/blob/2.4/code_of_conduct.md) to foster an open and dynamic environment for contributing and the exchange in the threat intelligence and information exchange field.

The [MISP roadmap](/roadmap.md) is mostly based on the user communities (e.g. private communities, CSIRTs communities, security researchers, ISACs - Information Sharing and Analysis Center, security providers, governmental or military organisations) relying on MISP to perform their duties of information sharing and analysis. 

Participating in the MISP project is easy and everyone can contribute following their ability. 
Get familiar with [how we use GitHub at MISP Project](/GITWORKFLOW.md), then read on for details on some ways you can contribute:

## Reporting bugs, suggesting features

The most common way to contribute to the MISP project is to report bugs, issues or suggest features. 

Each project ([MISP core](https://github.com/MISP/MISP/issues), [misp-modules](https://github.com/MISP/misp-modules/issues), [misp-book](https://github.com/MISP/misp-book/issues), [misp-taxonomies](https://github.com/MISP/misp-taxonomies/issues), [misp-galaxy](https://github.com/MISP/misp-galaxy/issues) or any of the other projects within the [MISP project organanisation](https://github.com/MISP/)) had their own issue management. 
Don’t forget that you can cross-reference issues from other sub-projects.

### Issue tracker guidelines
- **Use the provided issue template.** When reporting an issue on GitHub, please use one of the [issue templates](https://github.com/MISP/MISP/issues/new/choose). Do not delete it or remove parts of it. The issue template is carefully designed to elicit important information. Without this information, the issue is likely to be incomplete. It is also important to note the placement and content of the HTML comments in the issue template. These help us to have issues with a consistent format.
- **New issues should include all relevant information.** Add as much information as you can, including the version of MISP which you are running, screenshots with annotation, suggested features, and steps on how to reproduce an issue. You can also comment on existing issues; this is an indicator for us regarding the priority of certain features and how important these are to the users. If you know an answer or could help on a specific issue, we welcome all contributions including useful comments to reach a resolution. 
- **Security policy.** To disclose a security issue confidentially, please see the [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities) section.
- **New issues should not be duplicates of existing issues.** Before opening a new issue, search both open and closed issues to avoid duplicate issues.  For example, you may be experiencing a bug that was just fixed, in which case the report for that bug is probably closed. Here, it would be useful to view all bug reports, both open and closed, with the most recently updated sorted to the top.  If you find an issue that seems to be similar to yours, read through it. If you find an issue that is the same as or subsumes yours, leave a comment on the existing issue rather than filing a new one, even if the existing issue is closed. The MISP team will see your comment and reopen the issue, if appropriate. For example, you can leave a comment with additional information to help the maintainer debug it. Adding a comment will subscribe you to email notifications, which can be helpful in getting important updates regarding the issue. If you don’t have anything to add but still want to receive email updates, you can click the “Subscribe” button at the side or bottom of the comments. Commenting on existing issues is an indicator for us regarding the priority of certain features and how important these are to the users.
- **There are no guarantees that your issue will be addressed.** Creating a new issue is simply a way for you to submit an item for the MISP team’s consideration. It is up to the MISP team to decide whether or how to address your issue, which may include closing the issue without taking any action on it.  Even if your issue is kept open, however, you should not expect it to be addressed within any particular time frame, or at all.  At the time of this writing, there are well over 1.7 thousand open issues in the main MISP repo alone, not considering the other related repositories. The MISP team has its own [roadmap and priorities](/ROADMAP.md), which will govern the manner and order in which open issues are addressed.

### Following up afterward

If the MISP developers make a code change that resolves your issue, then your GitHub issue will typically be closed from the relevant patch message. 
There is one main MISP core branch, `2.4` (current stable version), that we consider as stable with frequent updates as hotfixes.
Features are developed in separated branches and then regularly merged into the stable branch. 
If you so choose, you can test the fix while it’s in the feature branch, or you can wait for it to land in the stable repository. 
If, after testing the fix, you find that it does not fix your bug, please leave a comment on your issue explaining the situation. 
When you do, we will receive a notification and respond to your issue or reopen it (or both). 
Please do not create a duplicate issue.

In other cases, your issue may be closed with a specific resolution, such as `R: invalid`, `R: duplicate`, or `R: wontfix`. 
Each of these labels has a description that explains the label. 
We’ll also leave a comment explaining why we’re closing the issue with one of these specific resolutions. 
If the issue is closed without one of these specific resolutions or a comment, then it means, by default, that your reported bug was fixed or your requested enhancement was implemented.

## Reporting security vulnerabilities

View our [Security Policy](https://github.com/MISP/MISP/security/policy).

## Contributing to MISP core

Before you get started, read our [coding guidelines](/CODINGSTYLE.md).

If you want to contribute to the [MISP core](https://github.com/MISP/MISP) project:

- First fork the [MISP core project](https://github.com/MISP/MISP)
- Branch off from 2.4 (2.4 branch is the main branch of development in MISP) `git checkout 2.4`
- Then create a branch for your own contribution (bug fixes, enhancement, new features) by typing `git checkout -b fix-glossy-user-interface`
- Work on your fix or feature (only work on that, avoid committing any debug functionalities, testing, or unused code)
- Commit your fix or feature (and sign it with GnuPG -- if you have a GnuPG key) with a meaningful commit message as recommended in our [Commit Messages Best Practices](https://github.com/MISP/MISP/wiki/CommitMessageBestPractices). MISP uses [gitchangelog](https://github.com/vaab/gitchangelog/blob/master/src/gitchangelog/gitchangelog.rc.reference) to generate changelog, so it's recommended that when writing commit messages, use `new:` for new features, `fix:` when it's a bug-fix or `chg` when it's re-factoring or clean-up.
- Push and then [open a pull-request](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request) via the GitHub interface.

For changes in categories and types see the [Categories & Types Changes CheckList](https://github.com/MISP/MISP/wiki/Categories-&-Types-changes-CheckList).

If you have never done a pull-request, there is [The beginner's guide to contributing to a GitHub project](https://akrabat.com/the-beginners-guide-to-contributing-to-a-github-project/)

Some recommendations to get your PR merged quickly:

- Small gradual changes are preferred over big and complex changes.
- If the changes require some documentation changes, a pull-request on [misp-book](https://github.com/MISP/misp-book) is strongly recommended.
- If the commit message contains all the information regarding the changes, it's easier for the maintainer to do the review. 
- Avoid committing sensitive information, debugging code, or unrelated code in the PR.

## Contributing to a JSON library (objects, taxonomies, galaxy or warning-list)

All of MISP's JSON format (galaxy, taxonomies, objects, or warning-lists) are described in a JSON Schema, named using the convention `schema_name.json`.
The TravisCI tests include JSON validation (via `jq`) and are validated with the associated JSON Schema.
When you update a JSON library, validate the associated JSON schema by running `jq_all_the_things.sh`.
This prompts the JSON validation tests (via `jq`) using [TravisCI](https://travis-ci.org/MISP). It should be fast and easy. 
If the checks fail, review your JSON. 
Once everything works, commit your code and make a pull request against the specific library.

Documentation (in PDF and HTML format) for the librairies are automatically generated from the JSON via [asciidoctor](https://asciidoctor.org/). Look at [this example](https://github.com/MISP/misp-galaxy/blob/main/tools/adoc_galaxy.py). 

## Contributing to MISP taxonomies

If you cannot find an existing taxonomy fitting your needs, you can extend an existing one (especially the ones that originated from the MISP project) or create a new one. To do this:
1. Create a JSON file describing your taxonomy as triple tags (e.g. check an existing one such as the [Admiralty Scale](https://github.com/MISP/misp-taxonomies/tree/master/admiralty-scale)) taxonomy
2. Create a directory matching your namespace
3. Put your machinetag file in the directory
4. (Optional, but recommended) Validate the JSON file using [jq](https://github.com/MISP/misp-taxonomies/blob/master/jq_all_the_things.sh) and run [the validator](https://github.com/MISP/misp-taxonomies/blob/master/validate_all.sh) to check if the JSON validates the schema.
5. Commit your change and create a pull request

Everyone can benefit from your taxonomy and it can be automatically enabled in information-sharing tools such as [MISP](https://www.github.com/MISP/MISP).

For more information, see the presentation slides on "[Information Sharing and Taxonomies Practical Classification of Threat Indicators using MISP](https://www.circl.lu/assets/files/misp-training/3.2-MISP-Taxonomy-Tagging.pdf)" given at the last MISP training in Luxembourg.

## Contributing to MISP galaxy

In the world of threat intelligence, there are many different models or approaches to order, classify or describe threat actors, threats, or activity groups. 
We welcome new ways of describing threat intelligence as the galaxy model allows you to reuse the ones you use or trust for your organization or community.

To contribute, fork the [project](https://github.com/MISP/misp-galaxy), update or create a galaxy or clusters and make a pull-request.

Before making a pull request, we strongly recommend validating the JSON file using [jq](https://github.com/MISP/misp-galaxy/blob/master/jq_all_the_things.sh) and run [the validator](https://github.com/MISP/misp-galaxy/blob/master/validate_all.sh) to check if the JSON validates the schema.

## Building software compatible with MISP formats and improving MISP formats

[MISP formats](https://github.com/MISP/misp-rfc) are open and free standards, which are actively based on the MISP core implementation. 
MISP formats are simple JSON formats implemented in various software including the MISP core application along with various libraries such as [PyMISP](https://github.com/MISP/PyMISP). 
We invite software developers to use the native MISP format for exchanging threat intelligence and support information sharing/analysis.

If you want to contribute to our IETF Internet-Draft for the MISP standard, [misp-rfc](https://github.com/MISP/misp-rfc) is the repository to propose changes. 
Each format folder has several files of different extensions, including XML and Markdown (MD). 
You should update only the Markdown file; the XML and ASCII for the IETF I-D are automatically generated.
If a major release or updates happen in the format, we will [publish the I-D to the IETF](https://datatracker.ietf.org/doc/search/?name=misp&
activedrafts=on&rfcs=on).

## Writing documentation

We will appreciate new documentation or improvements on our documentation, particularly [MISP Book](https://github.com/MISP/misp-book).
See our [specific guidelines on contributing to MISP Book](https://github.com/MISP/misp-book/blob/main/CONTRIBUTING.md).

## Automatic integration and testing

The majority of the repositories within the MISP GitHub organisation include automatic integration with TravisCI. 
Feedback and patches are welcome. 
For example, you can propose new tests that we could run on Travis CI, or suggest additional automatic tests including unit testing for the MISP core software Please explain the expected benefit of your work on MISP developers and users -- this will help us prioritize our work. 

## Testing new releases and updates

Testing new MISP releases and updates is one of the ways that you can contribute to the MISP Project. 
However, you should only attempt to do this if you know what you’re doing. Never rely on code that is in testing for critical work!
After your testing, we would be grateful for your feedback via GitHub issues. 

If you would like to test MISP and don’t want to do an installation, you can use automatically-generated VM images. See more on our [download page](https://www.misp-project.org/download/#virtual-images). 

## Translating MISP

Thank you for your interest in making MISP easier to use in your language!

We accept translations on Crowdin: https://crowdin.com/project/misp. 
Crowdin is a localization management platform that helps companies to translate their software. 
Note that CrowdIn is independent of MISP and they have their own [privacy policy](https://support.crowdin.com/privacy-policy/). 

You can help correct, improve, or complete the translations of MISP programs into your native language. 
MISP can be translated into more than 140 languages this way. 
Most of MISP can be translated directly online, through a simple web interface, after logging in with CrowdIn. 
To get started with using CrowdIn, you can [read their introductory article](https://support.crowdin.com/for-volunteer-translators/). 
Note that only reviewed translations are included in MISP.

If you want to go further, reach out to us if you want to help translate the MISP website or MISP Book. 

## For native English speakers

Most MISP developers are not native English speakers so you are more than welcome to correct or improve our English. 
For this, you can either submit a pull request or another way that suits you better to share your improvements with us.


## Improving the MISP experience

As a MISP user, you can contribute to our UX efforts by filling the [MISP User Experience Survey](https://misp-project.org/ux-survey).
The purpose of this survey is to assess the user experience of MISP and learn more about the needs of its users. 

If you're a UX researcher or designer and want to help with UX issues, look at [issues with the `UX` label](https://github.com/MISP/MISP/labels/UX) on our GitHub issue tracker, corresponding to things that we would like to see improved in the MISP user experience. If you have other ideas to improve MISP, let us know! Even if you don't implement your suggestions yourself, create issues with your ideas so that others can benefit from your insight.

You can also help us refine or enhance our [user personas](https://www.circl.lu/doc/misp/user-personas/) and [user stories](https://www.circl.lu/doc/misp/user-stories/). 

For any questions or comments related to UX, please get in touch with us at <ux@misp-project.org>

## Improving the website

We have identified some things that we would like to see improved on our website: see the [website-related issues on GitHub](https://github.com/MISP/misp-website/issues). We are also open to new suggestions on what should be improved. 

The website https://misp-project.org/ is built using Jekyll.
You can [build a local copy of the website](https://github.com/MISP/misp-website/issues) on your computer. 
Building the website produces a set of HTML pages stored on your system that you can open in your usual web browser even while working offline. 
Doing so is useful for writers and designers to see how their changes will apply to the website.
