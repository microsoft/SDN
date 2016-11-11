# Workflow  
Some people might be new to using Git and GitHub so here is a simple workflow to facilitite Pull Requests which can be reviewed and merged easily.

 1. Create a forked copy of the microsoft/sdn repo from https://github.com/microsoft/sdn 
 2. Clone that copy to your local machine (git clone https://github.com/*GitUserName*/sdn.git)
 3. Create a new branch on your local machine with a descriptive name to indicate the changes you will be making (git checkout -b *DescriptiveName*)
 4. Update and commit docs (git add, git commit, git push) to generate a preview viewable via GitHub (e.g. https://github.com/<GitUserName/blob/*DescriptiveBranchName*/*filename*.md)
 5. Iterate on this branch until satisfied
 6. Create a Pull Request into the master branch from https://github.com/Microsoft/sdn (Select Pull requests, New pull request) and compare across forks


At this point, the PR will be reviewed and merged into the master branch by one of the Maintainers.



