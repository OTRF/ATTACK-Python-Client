# Contributing Guidelines

When contributing to this repository, please share your proposal via a GitHub issue and our [discord](https://discord.com/invite/efBGmbQ) server.

This documentation contains a set of guidelines to help you during the contribution process.
We are happy to welcome all the contributions from anyone willing to improve/add new scripts to this project. Thank you for helping out and remember, **no contribution is too small.**

#### Table Of Contents

* [Code of Conduct](#code-of-conduct)
* [Submitting Contributions](#submit-contributions)
  * [Find An Issue](#step-0--find-an-issue)
  * [Fork The Project](#step-1--fork-the-project)
  * [Branch](#step-2--branch)
  * [Work on the issue assigned](#step-3--work-on-the-issue-assigned)
  * [Commit](#step-4--commit)
  * [Work Remotely](#step-5--work-remotely)
  * [Pull Request](#step-6--pull-request)

## Code of Conduct
This project and everyone participating in it is governed by the Contributor Covenant. Make sure to read it here: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Submit Contributions
Below you will find the process and workflow used to review and merge your changes.

### Step 0 : Find an issue
- Take a look at the Existing Issues or create your **own** Issues!
- Wait for the Issue to be assigned to you after which you can start working on it.
- Note : Every change in this project should/must have an associated issue.

### Step 1 : Fork the Project
- Fork this Repository. This will create a Local Copy of this Repository on your Github Profile. Keep a reference to the original project in `upstream` remote.
```
$ git clone https://github.com/<your-username>/ATTACK-Python-Client.git
# Navigate to the project directory.
$ cd Hacking-Scripts
$ git remote add upstream https://github.com/OTRF/ATTACK-Python-Client.git
```

- If you have already forked the project, update your copy before working.
```
$ git remote update
$ git checkout <branch-name>
$ git rebase upstream/<branch-name>
```

### Step 2 : Branch
Create a new branch. Use its name to identify the issue your addressing.
```
# It will create a new branch with name Branch_Name and switch to that branch
$ git checkout -b Branch_Name
```

### Step 3 : Work on the issue assigned
- Work on the issue(s) assigned to you.
- Add all the files/folders needed.
- After you've made changes or made your contribution to the project add changes to the branch you've just created by:
```
# To add all new files to branch Branch_Name
$ git add .
```
```
# To add only a few files to Branch_Name
$ git add <some files>
```

### Step 4 : Commit
- To commit give a descriptive message for the convenience of reviewer by:
```
# This message get associated with all files you have changed
$ git commit -m "message"
```
- **NOTE**: A PR should have only one commit. Multiple commits not allowed.

### Step 5 : Work Remotely
- Now you are ready to your work to the remote repository.
- When your work is ready and complies with the project conventions, upload your changes to your fork:

```
# To push your work to your remote repository
$ git push -u origin Branch_Name
```
- Here is how your branch will look.

### Step 6 : Pull Request
- Go to your repository in browser and click on compare and pull requests. Then add a title and description to your pull request that explains your contribution.
- Good Work! Your Pull Request has been submitted and will be reviewed by the moderators and merged.
