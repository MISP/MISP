# MISP Web UI – General – Onboarding Tutorial Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Tutorial – shown once to a new account](#onboarding-first-login) | |
| 2 | [Tutorial – sections offered to each role](#onboarding-launcher-roles) | |
| 3 | [Tutorial – Getting around](#onboarding-general) | |
| 4 | [Tutorial – Report an incident](#onboarding-report-incident) | |
| 5 | [Tutorial – Data models, Sync and Administration](#onboarding-pages) | |
| 6 | [Tutorial – Back, reload and skip](#onboarding-controls) | |

---


# E2E Tests

### Tutorial – shown once to a new account
<a id="onboarding-first-login"></a>

The tutorial opens by itself at the first login of a new account, and only once

1. Log in to MISP as `site-admin` and create a user `qa-tour-<timestamp>@admin.test` (organisation `ADMIN`, role `User`, with a password).
2. Log out and log in as the new user.
3. Click **Skip tutorial**.
4. Log out and log in again as the new user.

**Expected:** at step 2 the tutorial opens on "Welcome to MISP" (**Getting around · Step 1 of …**); at step 3 the message "Tutorial closed. Replay it from your account menu whenever you like." is shown; at step 4 the tutorial does not open again.

### Tutorial – sections offered to each role
<a id="onboarding-launcher-roles"></a>

The launcher only lists the sections the account can use

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Open the account menu and click **Replay the tutorial**.
4. Note the sections and their number of steps, then click **Close**.
5. Do the same as `org-admin` and as `user` of the organisation `ADMIN`.

**Expected:** `site-admin` sees Getting around, Report an incident, Data models, Sync and feeds, Administration; `org-admin` sees the same without Sync and feeds; `user` sees Getting around, Report an incident and Data models. The step counts match what each section then shows.

### Tutorial – Getting around
<a id="onboarding-general"></a>

Every step of "Getting around" points at the element it describes

1. Log in to MISP as `site-admin` (then as `org-admin` and `user`).
2. Open the account menu, click **Replay the tutorial**, and **Start this section** on **Getting around**.
3. Read each step and click **Next** until the end of the section.

**Expected:** each step shows its title and **Step n of N**, and highlights the element it talks about (menu, page header, search box, a row of the Events list…); no step stays without its highlight, and the tutorial does not stop on an error.

### Tutorial – Report an incident
<a id="onboarding-report-incident"></a>

The interactive part follows the real actions of the user

1. Log in to MISP as `site-admin`.
2. Open the account menu, click **Replay the tutorial**, and **Start this section** on **Report an incident**.
3. Follow the steps: click **Add Event** when asked, type `QA tour <timestamp>` in **Event Info**, click **Create Event Entry**, click **Add Attribute** when asked, then continue with **Next**.
4. In "Classify it", open an event, open the tag picker when asked; in "Share and publish it", read the steps to the end.
5. Delete the event `QA tour <timestamp>`.

**Expected:** after each click asked by the tutorial, it continues on the next step (also after the new event page loads); every step highlights its element; the section ends without error.

### Tutorial – Data models, Sync and Administration
<a id="onboarding-pages"></a>

The tutorial opens the pages it talks about

1. Log in to MISP as `site-admin`.
2. Start the sections **Data models**, **Sync and feeds** and **Administration** one after the other from **Replay the tutorial**.
3. Click **Next** through every step.

**Expected:** the tutorial opens each page by itself (taxonomies, tags, galaxies, warning lists, notice lists, feeds, servers, sharing groups, users, organisations, roles, API keys, server settings), highlights its header, and ends on "That is the tour".

### Tutorial – Back, reload and skip
<a id="onboarding-controls"></a>

The tutorial controls behave as labelled

1. Log in to MISP as `site-admin`.
2. Start the full tour from **Replay the tutorial**.
3. Check that **Back** is disabled on the first step, click **Next** twice, then **Back** once.
4. Reload the page.
5. Click **Skip section**, then **Skip this part**, then **Skip tutorial**.

**Expected:** **Back** returns to the previous step; after the reload the tutorial continues on the same step; **Skip section** opens the first step of the next section, **Skip this part** the next part, and **Skip tutorial** closes it with "Tutorial closed. Replay it from your account menu whenever you like."
