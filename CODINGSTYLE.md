# Coding guidelines for MISP developers

Maintaining proper coding style is very important for any large software project, such as MISP. Here’s why:

- It eases maintenance tasks, such as adding new functionality or generalizing code later
- It allows others (as well as the future you!) to easily understand fragments of code and what they were supposed to do, and thus makes it easier to later extend them with newer functionality or bug fixes
- It allows others to easily review the code and catch bugs
- It provides for an aesthetically pleasing experience when one reads the code
 
## General typographic conventions
- Maintain a maximum line length of 80 characters. Even though today’s monitors often are very wide and it’s often not a problem to have 120 characters displayed in an editor, maintaining shorter line lengths improves readability. It also allows others to have two parallel windows open, side by side, each with different parts of the source code.
- Naming conventions:
    - `ClassName`, 
    - `someVariable`, `someFunction`, `someArgument`
- Maintain a decent amount of horizontal spacing, e.g. add a space after `if` or before `{` in PHP, Python, JavaScript, and similar in other languages. Whether and where to also use spaces within expressions, such as `(y*4+8)` vs. `(y * 4 + 8)` is left to the developer’s judgment. Do not put spaces immediately after or before the brackets in expressions, so avoid constructs like this: `if ( condition )` and use ones like this: `if (condition)` instead.
- Use descriptive names for variables and functions. At a time when most editors have auto-completion features, there is no excuse for using short variable names.
- Comments should be indented together with the code, e.g. like this:
    ```
    class HttpClientJsonException extends Exception
    {
        /** @var HttpSocketResponse */
        private $response;
     }
    ```
## File naming conventions
- Never use spaces within file names
- **PHP:** Write file names in title case ,e.g. `AttachmentTool.php`
- **Python:** Write file names with small letters, use a dash to separate words, rather than underscores, e.g. `load_warninglists.py`
- **JavaScript:** Write file names with small letters, use dashes to separate words, rather than underscores, e.g. `bootstrap-colorpicker.js`

## General programming style guidelines
- Always prefer readability over trickiness! No need to use tricks to save a few lines of code.
- Make sure your code compiles and builds without warnings
- Always think first about interfaces (e.g. function arguments, or class methods) and data structures before you start writing the actual code.
- Use comments to explain non-trivial code fragments, or expected behavior of more complex functions, if it is not clear from their name.
- Do not use comments for code fragments where it is immediately clear what the code does. E.g. avoid constructs like this:

      function ret(tp, style, cont) {
        type = tp; content = cont;
        // Return style
        return style;
      }
- In production code, there should be little to no commented or disabled code fragments. Do not use comments to disable code fragments, unless you need to. But generally, there is little excuse to keep old, unused code fragments in the code. Instead, use the functionality provided by the source code management system, such as git. For example, create a special branch for storing the old, unused code – this way you will always be able to merge this code into upstream in the future.
- Try not to hardcode values in the code. 

## Commit message guidelines

Please attempt to follow our [commit messages best practices](https://github.com/MISP/MISP/wiki/CommitMessageBestPractices) when writing your git commit messages. 
Also, when committing changes that will resolve an issue once merged, include #NNNN in the commit message, NNNN being the issue number. 
Then, GitHub will automatically reference this commit on the corresponding issue, once the branch is pushed to our Git repository. 
For example:
```
chg: [doc] Fix spelling errors (#3120)
```
