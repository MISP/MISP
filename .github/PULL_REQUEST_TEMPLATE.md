## Generic requirements in order to contribute to MISP:

* One Pull Request per fix/feature/change/...
* Keep the amount of commits per PR as small as possible: if for any reason, you need to fix your commit after the pull request, please squash the changes in one single commit (or tell us why not)
* Always make sure it is mergeable in the default branch (as of today 2020-05-05: branch 2.4)
* Please make sure Travis CI works on this request, or update the test cases if needed
* Any major changes adding a functionality should be disabled by default in the config


#### What does it do?

If it fixes an existing issue, please use github syntax: `#<IssueID>`

#### Questions

- [ ] Does it require a DB change?
- [ ] Are you using it in production?
- [ ] Does it require a change in the API (PyMISP for example)?
