# ⚙️ MsgdPlug - MISP Multi Sharing Group Distribution Plugin

**MsgdPlug** is a plugin for **MISP (Malware Information Sharing Platform)** designed to bypass native single Sharing Group selection limits. It injects client-side controls and backend services into standard MISP views (`Add`, `Edit`, `View`, `Index`) allowing users to select multiple Sharing Groups simultaneously via dynamically evaluated **Sharing Group Blueprints**.

| Platform           | Pipeline Status                                                                                                                                                                                        |
|:-------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **GitHub Actions** | [![GitHub CI](https://img.shields.io/badge/GitHub_CI-Workflow-blue?logo=github&style=flat-square)](https://github.com/tetrapi/mim-misp-sharing-group-plugin-boilerplate/actions/workflows/ci.yml)            |
| **GitLab CI**      | [![GitLab CI](https://img.shields.io/badge/GitLab_CI-Pipelines-orange?logo=gitlab&style=flat-square)](https://git.tetrapi.pt/gp/mim/boilerplate/mim-misp-sharing-group-plugin-boilerplate/-/pipelines) |

[![License](https://img.shields.io/badge/License-AGPL%203.0-blue?style=flat-square)](LICENSE)

[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D%208.2-777BB4?logo=php&logoColor=white&style=flat-square)](https://www.php.net)

[![PHPStan](https://img.shields.io/badge/PHPStan-Level%2010-brightgreen?logo=php&logoColor=white&style=flat-square)](phpstan.neon)

[![Code Style](https://img.shields.io/badge/Code%20Style-PSR--12-yellow?logo=php&logoColor=white&style=flat-square)](.phpcs.xml)

[![MISP](https://img.shields.io/badge/MISP-v2.5-red?style=flat-square)](https://github.com/MISP/MISP)

[![MISP Repository](https://img.shields.io/badge/Go%20to-MISP%20Repository-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/MISP/MISP)

![Demo preview](images/demo1.gif)

---

## 🚀 Key Features

* **Seamless Native UI Overlay:** Injects custom multi-select components and modals directly into standard MISP forms (`Add`/`Edit`) and view interfaces (`View`/`Index`) using asynchronous JavaScript and AJAX.
* **Dynamic Blueprint Evaluation:** Evaluates multi-group selections on the fly, creating or reusing unified backend **Sharing Group Blueprints** without modifying MISP's core database schemas.
* **Interactive View/Index Inspection Modal:** Intercepts native sharing group links in `View` and `Index` modes to render a modal detailing all underlying member groups.
* **Granular RBAC & Email Whitelisting:** Fully respects native MISP permissions (`perm_sharing_group`) and provides an explicit user email allowlist for fine-grained permission control.
* **CSRF Token Lifecycle Management:** Features automatic CSRF token rotation (`nextToken`) across asynchronous requests to ensure form stability.
* **Comprehensive Test Suite:** Includes full PHPUnit coverage for Controllers, DTOs, Enums, Services, and Utilities.
* **Automated Bash Installer:** Provides a shell utility script (`msgd_installer.sh`) supporting automated backup, file patching, PHP syntax verification, and full restoration.

---

## ⚙️ How It Works & Workflows

### 1. Form Mode (`Add` / `Edit` Pages)
Instead of altering MISP's core database tables, **MsgdPlug** bridges multi-group distribution through native **Sharing Group Blueprints**.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        MISP Event / Attribute Form                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
    1. Fetch Sharing Groups         │ (MsgdApiController::getSharingGroups)
   ─────────────────────────────────┴─────────────────────────────────►
                                    │
    2. User selects multiple groups │ (MsgdFormUI / MsgdForm)
   ─────────────────────────────────┴─────────────────────────────────►
                                    │
    3. Evaluate Blueprint           │ (MsgdApiController::checkBlueprint)
   ─────────────────────────────────┼──────────────────────────────────►
                                    ├───► Blueprint Exists: Retrieve Group ID
                                    └───► Blueprint Absent: Generate & Execute Blueprint
                                                               (MsgdApiController::processGroups)
                                    │
    4. Inject Final Group ID        │
   ─────────────────────────────────▼──────────────────────────────────►
                  [ Standard MISP Form field: sharing_group_id ]
```

---

### 2. View & Index Inspection Mode (`View` / `Index` Pages)
When navigating MISP interface in `View` or `Index` mode, `MsgdPlug` replaces or enhances native sharing group badges with dynamic inspection controls.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      MISP View / Index Event Page                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
    1. Scan & Pattern Match Links   │ (Regex: /\/sharing_?groups\/view\/(\d+)/i)
   ─────────────────────────────────┴─────────────────────────────────►
                                    │
    2. Inject Inspection Controls   │ (TEMPLATES.INDEX_VIEW_BTN)
   ─────────────────────────────────┴─────────────────────────────────►
                                    │
    3. User clicks Inspection button│ (SELECTORS.INDEX_VIEW_BTN -> #msgdViewModal)
   ─────────────────────────────────┴─────────────────────────────────►
                                    │
    4. Fetch Blueprint Member Groups│ (GET /msgd_plug/msgd_api/getBlueprintRulesGroups?group={id})
   ─────────────────────────────────┼──────────────────────────────────►
                                    ├───► Success: Render Member Table (TEMPLATES.INFO_TABLE)
                                    ├───► Empty: Render Feedback (TEMPLATES.FEEDBACK_EMPTY)
                                    └───► Error: Render Feedback (TEMPLATES.FEEDBACK_ERROR)
```

---

## 📁 Plugin Structure

```text
MsgdPlug
├── Config
│   └── bootstrap.php
├── Controller
│   ├── MsgdApiController.php
│   └── MsgdPlugAppController.php
├── Lib
│   ├── DTO
│   │   ├── MsgdBlueprintDTO.php
│   │   ├── MsgdBlueprintRulesDTO.php
│   │   ├── MsgdCheckBlueprintDTO.php
│   │   ├── MsgdGetBlueprintRulesGroupsDTO.php
│   │   ├── MsgdGetSharingGroupsDTO.php
│   │   ├── MsgdMirrorGroupsDTO.php
│   │   ├── MsgdProcessGroupsDTO.php
│   │   ├── MsgdProcessResultDTO.php
│   │   ├── MsgdSharingGroupDTO.php
│   │   └── MsgdUserDTO.php
│   ├── Enum
│   │   ├── MsgdMispActionEnum.php
│   │   ├── MsgdMispDistributionLevelEnum.php
│   │   ├── MsgdPluginActionEnum.php
│   │   ├── MsgdPluginConfigEnum.php
│   │   ├── MsgdPluginFileEnum.php
│   │   └── MsgdPluginStatusEnum.php
│   ├── Service
│   │   ├── MsgdApiControllerService.php
│   │   ├── MsgdBlueprintService.php
│   │   └── MsgdSharingGroupService.php
│   ├── Utility
│   │   ├── MsgdLoggerUtility.php
│   │   └── MsgdSanitizerUtility.php
│   └── Voter
│       └── MsgdBlueprintVoter.php
├── Test
│   └── Case
│       ├── Controller
│       │   ├── MsgdApiControllerTest.php
│       │   └── MsgdPlugAppControllerTest.php
│       └── Lib
│           ├── DTO
│           │   ├── MsgdBlueprintDTOTest.php
│           │   ├── MsgdBlueprintRulesDTOTest.php
│           │   ├── MsgdCheckBlueprintDTOTest.php
│           │   ├── MsgdGetBlueprintRulesGroupsDTOTest.php
│           │   ├── MsgdGetSharingGroupsDTOTest.php
│           │   ├── MsgdMirrorGroupsDTOTest.php
│           │   ├── MsgdProcessGroupsDTOTest.php
│           │   ├── MsgdProcessResultDTOTest.php
│           │   ├── MsgdSharingGroupDTOTest.php
│           │   └── MsgdUserDTOTest.php
│           ├── Service
│           │   ├── MsgdApiControllerServiceTest.php
│           │   ├── MsgdBlueprintServiceTest.php
│           │   └── MsgdSharingGroupServiceTest.php
│           ├── Utility
│           │   ├── MsgdLoggerUtilityTest.php
│           │   └── MsgdSanitizerUtilityTest.php
│           └── Voter
│               └── MsgdBlueprintVoterTest.php
├── View
│   ├── Elements
│   │   ├── Common
│   │   │   ├── msgd_templates.ctp
│   │   │   └── msgd_utils.ctp
│   │   ├── Form
│   │   │   └── msgd_form.ctp
│   │   └── View
│   │       └── msgd_view.ctp
│   └── Helper
│       └── MsgdInjectorHelper.php
└── webroot
    ├── css
    │   └── msgd_style.css
    └── js
        ├── msgd_form.js
        ├── msgd_form_ui.js
        ├── msgd_utils.js
        └── msgd_view.js
```

---

## 📝 File & Module Descriptions

#### 📁 `Config/`
* **`bootstrap.php`**: Registers plugin paths, configures class autoloader aliases, and bootstraps listeners upon MISP initialization.

#### 📁 `Controller/`
* **`MsgdPlugAppController.php`**: Parent controller providing shared security validations, session permission checks, and standard JSON response formatting.
* **`MsgdApiController.php`**: Handles REST API requests for checking user permissions, fetching sharing groups, querying blueprint rules, checking group combinations, and executing group merging.

#### 📁 `Lib/`
* **`DTO/`**: Strongly typed Data Transfer Objects (`MsgdBlueprintDTO`, `MsgdCheckBlueprintDTO`, `MsgdProcessGroupsDTO`, etc.) that parse, validate, and structure API payloads.
* **`Enum/`**: Enumerations replacing magic strings/numbers across MISP distribution levels, plugin configurations, status flags, and asset paths (`MsgdMispActionEnum`, `MsgdPluginConfigEnum`, `MsgdPluginStatusEnum`, etc.).
* **`Service/`**: Decoupled domain service layer.
  * **`MsgdApiControllerService.php`**: Coordinates input validation, service invocation, and API response compilation.
  * **`MsgdBlueprintService.php`**: Logic engine for assessing blueprint existence, compiling rules, and executing blueprint generation.
  * **`MsgdSharingGroupService.php`**: Query interface for standard MISP Sharing Group retrieval, caching, and member filtering.
* **`Utility/`**: Cross-cutting support tools.
  * **`MsgdLoggerUtility.php`**: Standardized system logging wrapper handling plugin exception traces.
  * **`MsgdSanitizerUtility.php`**: Input sanitization and XSS prevention functions for dynamic HTML components.
* **`Voter/`**: Authorization layer encapsulating access control logic (`MsgdBlueprintVoter.php`) to validate user permissions before executing operations on blueprints or sharing groups.

#### 📁 `Test/`
* **`Case/`**: Full PHPUnit test suite mirroring the entire `Lib/` (including DTOs, Services, Utilities, and Voters) and `Controller/` tree for integration and unit testing.

#### 📁 `View/`
* **`Elements/Common/`**:
  * `msgd_templates.ctp`: HTML client-side structural templates (`#tpl-msgd-index-view-btn`, `#tpl-msgd-info-table`, `#tpl-msgd-feedback-loading`, etc.).
  * `msgd_utils.ctp`: Injector element exporting global JavaScript configuration (`window.MsgdUtilsConfig`) and runtime utilities.
* **`Elements/Form/`**:
  * `msgd_form.ctp`: Script bootstrap exporting `window.MsgdFormConfig` for `Add`/`Edit` form integration.
* **`Elements/View/`**:
  * `msgd_view.ctp`: Script bootstrap exporting `window.MsgdViewConfig` for `View`/`Index` inspection overlays.
* **`Helper/`**:
  * `MsgdInjectorHelper.php`: Evaluates current MISP controller/action context and injects corresponding `.ctp` elements into standard layouts.

#### 📁 `webroot/`
* **`css/msgd_style.css`**: Stylesheet for modal overlays, floating toolbars, responsive tables, lock icons, and notifications.
* **`js/`**:
  * `msgd_utils.js`: Core runtime handling notification, string escaping, template rendering, and AJAX queueing.
  * `msgd_form_ui.js`: DOM manipulation engine managing selection lists, drag interactions, search filters, and table renders.
  * `msgd_form.js`: Form controller managing submission hooks, asynchronous CSRF token refresh, and blueprint processing on `Add`/`Edit` pages.
  * `msgd_view.js`: Module (`MsgdViewBase`) handling regex URL detection, inspection button injection, `#msgdViewModal` lifecycle, and blueprint member group rendering.

---

## 🛠️ Configuration Parameters

`MsgdPlug` registers native Server configurations in MISP (`app/Config/config.php` and `app/Model/Server.php`). These parameters are configurable via the MISP Server Settings administrative interface or directly inside the configuration array.

| Configuration Key                            | Level |  Type   | Default | Description                                                                                             |
|:---------------------------------------------|:-----:|:-------:|:-------:|:--------------------------------------------------------------------------------------------------------|
| `Plugin.MsgdPlug_enabled`                    |   1   | Boolean | `true`  | Master toggle to enable or disable the plugin system-wide.                                              |
| `Plugin.MsgdPlug_use_ids`                    |   2   | Boolean | `false` | Strategy for group rules (`true` = numeric `id`, `false` = `uuid`).                                     |
| `Plugin.MsgdPlug_debug`                      |   2   | Boolean | `false` | Enables detailed log output via `MsgdLoggerUtility`.                                                    |
| `Plugin.MsgdPlug_controller_whitelist`       |   2   | String  |  `'*'`  | List of MISP controllers to inject scripts into (`*` = all, `none` = disable, or comma-separated list). |
| `Plugin.MsgdPlug_user_permissions_whitelist` |   0   | String  | `none`  | Email allowlist for non-perm_sharing_group  users (`*` = all, `none` = disabled, or email list).        |

### Parameter Details

* **`Plugin.MsgdPlug_enabled`**
  Activates or deactivates the plugin system-wide. When set to `false`, UI injection is halted and API endpoints return unauthorized standard error responses.

* **`Plugin.MsgdPlug_use_ids`**
  Determines how sharing group associations are recorded in blueprint rules.
  * `false` (Default): Uses group UUIDs. Recommended for federated MISP instances to guarantee cross-instance identity alignment.
  * `true`: Uses local internal numeric database IDs.

* **`Plugin.MsgdPlug_debug`**
  Toggles verbose error tracing. When enabled, exceptions and failed authorization attempts are logged directly into MISP log files.

* **`Plugin.MsgdPlug_controller_whitelist`**
  Restricts JavaScript injection to designated MISP controllers.
  * `*`: Enables injection globally across all supported controllers.
  * `none`: Disables UI injection everywhere.
  * `events, attributes`: Limits UI overlays strictly to Event and Attribute management pages.

* **`Plugin.MsgdPlug_user_permissions_whitelist`**
  Defines authorization rules for users who lack MISP's native `perm_sharing_group` privilege:
  * Users with native `perm_sharing_group` permissions are always granted full access.
  * `*`: All authenticated users are authorized to generate dynamic blueprints only via plugin.
  * `none`: Only users possessing native `perm_sharing_group` permissions can generate blueprints.
  * `user1@org.com, user2@org.com`: Explicit list of authorized user email addresses.

---

## 📡 API Reference (`MsgdApiController`)

All API routes are hosted under `/msgd_plug/msgd_api/` and require active MISP authentication sessions.

### 1. Check User Permission
Verifies if the current user is authorized to generate blueprints.
* **Route:** `GET /msgd_plug/msgd_api/checkUserPermission`
* **Response (Success - 200 OK):**
  ```json
  {
    "status": "success",
    "allowed": true
  }
  ```

---

### 2. Fetch Sharing Groups
Retrieves available sharing groups accessible to the logged-in user.
* **Route:** `GET /msgd_plug/msgd_api/getSharingGroups`
* **Query Parameters:** `all` *(bool, optional)* — `1` fetches all groups; `0` excludes blueprint-generated groups.
* **Response (Success - 200 OK):**
  ```json
  {
    "status": "success",
    "groups": {
      "12": "CERT_Group_Alpha",
      "15": "CSIRT_Group_Beta"
    }
  }
  ```

---

### 3. Get Blueprint Member Groups
Resolves individual sharing groups contained within a specific merged blueprint (used by `msgd_view.js`).
* **Route:** `GET /msgd_plug/msgd_api/getBlueprintRulesGroups`
* **Query Parameters:** `group` *(int, required)* — Target Blueprint Sharing Group ID.
* **Response (Success - 200 OK):**
  ```json
  {
    "status": "success",
    "groups": [
      { "id": "12", "uuid": "5e8f...", "name": "CERT_Group_Alpha" },
      { "id": "15", "uuid": "7a2b...", "name": "CSIRT_Group_Beta" }
    ]
  }
  ```

---

### 4. Check Blueprint Existence
Checks whether a blueprint matching the chosen group combination already exists.
* **Route:** `POST /msgd_plug/msgd_api/checkBlueprint`
* **Payload:**
  ```json
  {
    "data": {
      "MsgdPlug": {
        "groups": ["12", "15"]
      }
    },
    "_Token": { "key": "csrf_token_string" }
  }
  ```
* **Response (Success - 200 OK):**
  ```json
  {
    "status": "success",
    "exists": false,
    "nextToken": "refreshed_csrf_token_string"
  }
  ```

---

### 5. Process Group Combination
Generates or retrieves a single merged Sharing Group from selected groups.
* **Route:** `POST /msgd_plug/msgd_api/processGroups`
* **Payload:**
  ```json
  {
    "data": {
      "MsgdPlug": {
        "groups": ["12", "15"],
        "customName": "Merged CERT & CSIRT Group"
      }
    },
    "_Token": { "key": "csrf_token_string" }
  }
  ```
* **Response (Success - 200 OK):**
  ```json
  {
    "status": "success",
    "group": {
      "sharingGroupId": "42",
      "sharingGroupName": "Merged CERT & CSIRT Group"
    },
    "nextToken": "refreshed_csrf_token_string"
  }
  ```

---

## ⚡ Automated Installation

An interactive bash installer script (`msgd_installer.sh`) handles plugin deployment, core file patching, syntax verification, timestamped backups, and automated rollbacks.

> ⚠️ **Important Warnings & Prerequisites:**
> - Set `MISP.live = false` before installation, and set it back to `true` only after verifying that everything works correctly.
> - If MISP encounters issues post-installation, re-run the script, select **Restore (Option 4)**, choose the backup created prior to installation, and proceed with manual setup.
> - Although the script creates automatic backups, it is **strongly recommended** to manually back up the following core files before proceeding:
>   - `/var/www/MISP/app/Config/config.php`
>   - `/var/www/MISP/app/Config/bootstrap.php`
>   - `/var/www/MISP/app/Model/Server.php`
>   - `/var/www/MISP/app/Controller/Component/ACLComponent.php`

Copy or clone the repository to the root directory (`/`) on your server and follow the steps below. Once you confirm MISP is running smoothly, you may safely remove the installer repository.

**Interactive Mode:**
```bash
chmod +x msgd_installer.sh
sudo ./msgd_installer.sh
```

**Non-Interactive / Direct Installation:**
```bash
sudo ./msgd_installer.sh --auto
```

![Demo preview](images/demo2.gif)

### 🛠️ Installer Capabilities

1. **Deployment:** Copies `MsgdPlug` to `/var/www/MISP/app/Plugin/MsgdPlug`.
2. **Automated Backups:** Generates timestamped backups (`.bak_YYYYMMDDHHMMSS`) before modifying core files.
3. **Bootstrap Registration:** Appends plugin initialization configuration.
4. **ACL Whitelisting:** Registers `msgdApi` controller endpoints into MISP's Access Control List (ACL).
5. **Syntax Validation:** Runs `php -l` checks on modified files post-install to prevent breaking changes.

---

## 📖 Manual Installation Guide

> ⚠️ **Prerequisites & Manual Backups:**
> - Set `MISP.live = false` first, and set it back to `true` only after verifying that everything is operating correctly.
> - It is **strongly recommended** to manually back up the following core files before proceeding:
>   - `/var/www/MISP/app/Config/config.php`
>   - `/var/www/MISP/app/Config/bootstrap.php`
>   - `/var/www/MISP/app/Model/Server.php`
>   - `/var/www/MISP/app/Controller/Component/ACLComponent.php`

To configure MISP core files manually, follow the steps below:

### Step 1: Copy Plugin Directory
```bash
cp -r MsgdPlug /var/www/MISP/app/Plugin/
```

### Step 2: Register Plugin Bootstrapping
**File:** `/var/www/MISP/app/Config/bootstrap.php`

```php
if (Configure::read('Plugin.MsgdPlug_enabled')) {
    CakePlugin::load('MsgdPlug', array('bootstrap' => true, 'routes' => true));
}
```

### Step 3: Add Configuration Options
**File:** `/var/www/MISP/app/Config/config.php`

```php
'Plugin' => 
  array (
    'MsgdPlug_enabled' => true,
    'MsgdPlug_use_ids' => false,
    'MsgdPlug_debug'   => false,
    'MsgdPlug_controller_whitelist' => '*',
    'MsgdPlug_user_permissions_whitelist' => 'none',
```

### Step 4: Configure Access Control List (ACL)
**File:** `/var/www/MISP/app/Controller/Component/ACLComponent.php`

```php
const ACL_LIST = array(
    'msgdApi' => array(
        'processGroups'           => array('*'),
        'getSharingGroups'        => array('*'),
        'getBlueprintRulesGroups' => array('*'),
        'checkBlueprint'          => array('*'),
        'checkUserPermission'     => array('*'),
    ),
```

### Step 5: Register UI Server Settings
**File:** `/var/www/MISP/app/Model/Server.php`

```php
'Plugin' => array(
    'branch' => 1,
    'MsgdPlug_enabled' => array(
        'level' => 1,
        'description' => 'Enable or disable plugin.',
        'value' => true,
        'test' => 'testBool',
        'type' => 'boolean',
        'null' => true,
    ),
    'MsgdPlug_use_ids' => array(
        'level' => 2,
        'description' => 'Use IDs instead of UUIDs in blueprint rules to identify sharing groups.',
        'value' => false,
        'test' => 'testBool',
        'type' => 'boolean',
        'null' => true,
    ),
    'MsgdPlug_debug' => array(
        'level' => 2,
        'description' => 'Enable or disable debug logs.',
        'value' => false,
        'test' => 'testBool',
        'type' => 'boolean',
        'null' => true,
    ),
    'MsgdPlug_controller_whitelist' => array(
        'level' => 2,
        'description' => 'Comma-separated list of controllers where MsgdPlug is injected. Use * for global, none to disable.',
        'value' => '*',
        'test' => 'testForEmpty',
        'type' => 'string',
        'null' => true,
    ),
    'MsgdPlug_user_permissions_whitelist' => array(
        'level' => 0,
        'description' => 'Allowlist of users without [perm_sharing_group] permission authorized to generate blueprints (* = all, none = nobody, or email list).',
        'value' => 'none',
        'test' => 'testForEmpty',
        'type' => 'string',
        'null' => true,
    ),
)
```

---

## 💻 Local Development Environment (`dev.sh`)

For developers building or extending `MsgdPlug`, a unified CLI management script (`dev.sh`) is provided to automate Docker orchestration, IDE autocompletion stubs, unit testing, and environment resets.

**Make it executable and launch the CLI:**
```bash
chmod +x dev.sh
./dev.sh
```

### 🛠️ Developer CLI Capabilities

![Demo preview](images/demo3.gif)

1. **Deploy & Run Installer (Option 1):** Spins up the containerized MISP environment (`docker-compose-dev.yml`), executes `msgd_installer.sh --auto`, synchronizes IDE stubs, and prints access credentials parsed directly from `.env`.
2. **Run All Unit Tests (Option 2):** Triggers the PHPUnit test suite inside the `misp-core` container against all `MsgdPlug` test cases (`/Test/Case/`).
3. **Sync IDE Stubs (Option 3):** Extracts MISP core classes, Models, Controllers, and CakePHP framework files from the container into a local `.misp-stubs/` folder to enable full IDE autocompletion.
4. **Stop Docker Containers (Option 4):** Safely stops all development containers while preserving database state and configuration.
5. **Purge Docker Data (Option 5):** Performs a complete reset by destroying containers, wiping persistent database volumes, and cleaning up `.misp-stubs/`.

---

## 🧪 Manual Testing

The plugin includes unit and integration tests under `Test/Case/`:

### Running All Test Cases

To execute the entire test suite for the **MsgdPlug**, run the following command in misp-core (docker container) terminal:

```bash
/var/www/MISP/app/Vendor/bin/phpunit --bootstrap /var/www/MISP/app/Lib/cakephp/lib/Cake/Test/bootstrap.php /var/www/MISP/app/Plugin/MsgdPlug/Test/Case/
```

### Running Specific Test Cases

To run a single test file instead of the entire test suite, append the relative path of the specific test case file to the command. For example:

```bash
/var/www/MISP/app/Vendor/bin/phpunit --bootstrap /var/www/MISP/app/Lib/cakephp/lib/Cake/Test/bootstrap.php /var/www/MISP/app/Plugin/MsgdPlug/Test/Case/Controller/MsgdApiControllerTest.php
```

---

## 💡 Post-Installation Actions

After updating configuration files or running the installer script, clear the CakePHP cache and restart your web server:

```bash
sudo /var/www/MISP/app/Console/cake Admin clearCache
sudo systemctl restart apache2 # or nginx / php-fpm
```
---
## 📄 License & Authors

![creatores](images/creatores.png)

* **Authors:** TETRAPI SA, Lino Pacheco
* **License:** GNU Affero General Public License v3.0 (`AGPL-3.0`)
