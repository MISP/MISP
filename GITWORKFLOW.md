#  How we use GitHub

MISP issues and code are managed on [GitHub](https://github.com/MISP).
This page focuses on aspects of GitHub usage that are specific to MISP.
This workflow is not set in stone: it will evolve based on what we learn while using GitHub.
For general GitHub usage information, see the [GitHub user documentation](https://docs.github.com/en/github).

## Get started

To create your GitHub account, visit the [registration page](https://github.com/join) in a web browser.
Then you will be allowed to open new issues, create merge requests, and fork your copy of our repositories.

## Organisation

All of our repositories are available under the [MISP GitHub account](https://github.com/MISP).
The main Git repository and most issues live in the [MISP/MISP repository](https://github.com/MISP/MISP).

We use git to maintain all code for MISP Project. We have divided the project into several components, each of which has its own separate repository.  For example:
- `MISP.git` – The core MISP code.
- `misp-taxonomies.git` – Taxonomies used in MISP taxonomy system and can be used by other information-sharing tools.
- `misp-galaxy.git` – Clusters and elements to attach to MISP events or attributes (like threat actors).
- `misp-warninglists.git` – Warning lists to inform users of MISP about potential false positives or other information in indicators.

MISP code is divided into many git repositories for the following reasons:
    - This creates natural boundaries between different code blocks, enforcing proper interfaces, and easing independent development to be conducted on various code parts at the same time, without the fear of running into conflicts.
    - By maintaining relatively small git repositories, it is easy for new developers to understand the code and contribute new patches, without the need to understand all the other code.
    - Code repositories represent also licensing boundaries. So, e.g. because misp-objects and PYMISP are maintained in two different repositories, it is possible to have the latter under a CC0 1.0 Universal license, while keeping the former under a simplified 2-BSD license.

### Git branches organisation

MISP uses several branches:

- Version branch: This is the default branch, and it is named to reflect the latest MISP release. At the time of writing, the default branch is `2.4`
- Topic branches: We use topic branches, sometimes called `fix-*` and `feature-*`, respectively aimed at fixing a single bug and implementing a single new feature. Once ready, a topic branch is merged into the appropriate branch (generally the default branch). Until it has been merged, a topic branch's history may be rewritten.

When the MISP developers make a code change that resolves an issue, the GitHub issue will typically be closed from the relevant patch message. 
The main MISP core branch, `2.4` (current stable version), that we consider as stable with frequent updates as hotfixes. 
Features are developed in separated branches and then regularly merged into the `2.4` stable branch.

## How we use GitHub metadata

On GitHub, issues and merge requests have metadata.
Being consistent in the use of GitHub metadata makes collective work smoother.

### Title and description
The title should be a short but clear description of what this is about. Some people are case sensitive, please try to consider that.

### Status and resolution

Open issues may have a status label, starting with `S:`. Each label has a description of what it represents. 
See the [list of status labels](https://github.com/MISP/MISP/labels?q=S%3A+), along with their descriptions.

Closed issue may have up to one resolution label, starting with `R:`. See the [list of resolution labels](https://github.com/MISP/MISP/labels?q=R%3A+) and their descriptions. When an issue does not fit into MISP's mission, we reject it by creating a comment explaining why it's being rejected, closing the issue, and the `R: wontfix` label. When an issue is closed as a duplicate, we create a comment that mentions the other, duplicated issue and add the `R: duplicate` label. If the issue is closed without one of the specific resolutions or a comment, then it means, by default, that the issue in question was fixed or the requested enhancement was implemented.

The main advantage of using these labels is to organize and visualize issues on Issue Boards.
Using these labels accurately improves the team's workflow.

### Assignee

We use the Assignee field in a way that helps us organize our work as a team, focus on what matters most currently, and avoid individual over-commitment and feelings of failure.
To this aim, most tasks should be up for grabs for anyone who has spare capacity and the required skills.
So in general, issues and merge requests should not be assigned to anyone.

This being said, we do assign them if at least one of these conditions is met:

- Someone is actively working on it.
- The task is important and urgent.
- The milestone is set to the next MISP release. 
- Only one of us can complete the task. This helps identify bottlenecks and over-commitment.

### Milestone

Sometimes, [Milestones](https://github.com/MISP/MISP/milestones) are treated as a commitment that other MISP contributors should be able to rely on.
Other times, it is used it as a pool of tasks they want to have on their short-term radar.

### Type of work

To indicate the type of work that's needed to complete the next step on an issue, we use labels that start with `T:`. 
See the [list of the 'type of work' labels](https://github.com/MISP/MISP/labels?q=t%3A) and their descriptions.

### Other labels

See our [full list of labels](https://github.com/MISP/MISP/labels) for other uncategorized labels we use. 

## Relationships between issues

GitHub is a bit limited when it comes to expressing semantic relationships between issues. Here is how we can overcome these limitations.
- Parent/subtask: Issues with the `T: meta` label indicate parent issues that have subtasks under it. In the child issues, a comment will be added mentioning the parent issue. 
- Related issues: Related issues can be listed either in the description or in a comment. Either way, this adds a message in the activity stream of the referenced issue, with a link to the referencing issue.

## How to document progress

### Create and update issues

For details about labels, see [metadata](#how-we-use-github-metadata). If you are very certain to work on the issue, leave a comment expressing your interest or ask to be assigned to it to avoid duplicate work. 

All the knowledge useful to the others should be kept on that issue, or at least linked from there.
When committing changes that will resolve an issue once merged, please include #NNNN in the commit message, NNNN being the issue number. Then, GitHub will automatically reference this commit on the corresponding issue, once the branch is pushed to our Git repository. For example:

```
chg: [doc] Fix spelling errors (#3120)
```

### Report progress or failure

It is important to:
- Keep the team informed of how you feel committed to issues assigned to you, and about the timeline you're envisioning.
- Avoid individual over-commitment & feelings of failure.

If you don't think you will manage to work on an issue any time soon, it's often best to make this clear on the issue or to de-assign yourself.

### Propose changes

We use Pull Requests (aka. PRs) to propose, review, and merge changes. 
You can comment on issues and pull requests. 
[Our code of conduct](https://github.com/MISP/MISP/blob/2.4/code_of_conduct.md) applies. 

To submit your work:
- Fork us on our GitHub
- Push your work to a dedicated git topic branch
- Once you would like your branch to be reviewed, and possibly merged, submit it by creating a pull request (PR). In this new PR, use the description field to summarize what problem this PR will fix, in terms of impact on users, and reference the issues this PR will solve, e.g "Closes #xxx, #yyyy".

Follow these conventions when submitting changes to any MISP Project repository:
- Submit one pull request (PR) per fix/feature/change. Don't split one feature into multiple PRs. Similarly, do not join several fixes and features into one pull request. 
- Keep the number of commits per PR as small as possible. If for any reason, you need to fix your commit after the pull request, please squash the changes in one single commit (or tell us why not).
- Always ensure your PR is mergeable in the default branch.
- Make sure Travis CI works on the PR, or update the test cases if needed.
- Any major changes adding a functionality should be disabled by default in the config.

### Request input from someone else

If you need input from someone else on an issue or pull request, ask your question in a comment there, mentioning them with their GitHub login name: @nick. If you want to raise the attention of every single member of a team, mention it with the name of the corresponding group: @xyz-team. GitHub will send them an email notification about it.  

### Act upon input requests

It's important to provide the requested information as quickly as you can, to make the MISP contribution process more efficient and enjoyable.

When input is requested from you on an issue or pull request with @nick:
- GitHub may send you an email notification
- Please ensure your GitHub email notification settings and your email setup allow you to receive and notice these messages.

When you receive such a request, if you cannot provide the requested input immediately, you're responsible for keeping track of this task. For example, by creating a new issue assigned to yourself, or using whatever personal organization tools work for you.

## Automatic integration and testing

MISP core uses CodeQL and LGTM for some code analysis and security checks. When you submit a PR, consider the results of checks. Also, ensure that your code builds without errors. 

The majority of the repositories within the MISP GitHub organisation include automatic integration with [TravisCI](https://travis-ci.org/MISP).
If you contribute and make a pull request, verify if your changes affect the result of the tests.
Automatic integration is not perfect including Travis but it’s a quick way to catch new bugs or major issues in contribution.
When you make a pull request, TravisCI is automatically called. If there are failing checks, no worries, review the output at Travis (it’s not
always you).

## Access control

If you need to do something in GitHub and you appear to lack the needed credentials, please ask the MISP team to grant you more power.
For example, you will need "Triage" access to add labels or assign issues. See [GitHub's access permissions documentation](https://docs.github.com/en/github/getting-started-with-github/access-permissions-on-github).
