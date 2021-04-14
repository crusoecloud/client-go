# Go Template

This project is used as a template for Crusoe's Go projects. It contains the common CI/CD files and directory structure that we use in our projects.

## Usage

### Setup
First, you should rename the module by changing the first line in `go.mod`. The same change should be made in the go files included here if you decide to keep them. Look for instances of `TODO(template)` in this repo for places where you might need to change something.

### Go executable
If you're creating an executable, rename the subdir under `cmd` to the name of your executable and use the `main.go` file there as the entrypoint. It should be a thin entrypoint and depend on packages in the `internal` dir for the actual logic. You'll also need to rename the project name and executable name in `Makefile`.

### Go library
If you're creating a library, delete the `cmd` dir. Any packages you want to be exported from the library (i.e. that you want to depend on in other repos) should be in the top level dir of the repo. Any that you don't want to be exported should go in the `internal` dir.

### Other files
Update the Makefile as you see fit, but make sure to have a `ci` directive that can be used by our Gitlab runner to verify commits. Please see the `.gitlab-ci.yml` file for the base CI setup. You can also update that file if you need to perform other types of operations during CI.

The `.golangci.yml` file should be left untouched unless there is a good reason to change the settings for or delete one of the linters. When submitting a MR that does remove support for a linter, please provide the reasoning in an inline comment in that file.