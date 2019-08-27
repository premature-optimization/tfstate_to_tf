# tfstate_to_tf
Converter from Terraform Statefiles to Terraform code (in HCL)

**USE CASE**

This converter has been extremely useful for refactoring existing Terraform managed resource code into something else.

For instance, I created this tool because I was working with a Terraform repository with tons of workspaces, about 16 modules, and about 7 layers of interpolation (variables set in workspace variables, passed to a module, grabbed by other modules as an output, calculated through HCL functions, and reset as another output) and it was difficult to find a foothold to begin simplifying/refactoring the code.

I used this script in order to grab all of the end-values for the resources and format to flat Terraform code, as well as pushing the values to a YAML file (to be added soon) in order to use that as a base configuration.

This is my first published Python tool, so it's definitely in need of some optimization. But I've found it very useful, I hope you will as well!

**SUPPORTED RESOURCES**
Only AWS VPC and DNS resources are supported at the moment.
You can add support for a new resource by creating that resource function (please keep naming consistent with TF resource name), adding an `elif` statement to check for that resource and send the resource values, and creating a Jinja2 template for generating the Terraform code for that resource.

If there is a lot of attention for this script, I'll work a bit harder at including EC2, S3, DynamoDB, and IAM resources. Once AWS is pretty robust, I'll look into adding support for GCP resources as well.

**HOW TO USE**

You will need:

- A Terraform state file (gotten from `terraform state pull >(your_filename)` command
- Python 2 or 3 (I believe Python 2 templates are stale, so if you have issues use Python3)
- The following `pip` modules installed:
    jinja2

Then, basically run `python3 main.py`
Enter the full filepath, e.g. `./mystate.tfstate`

**WHAT IT WILL DO**

1. Create a directory named after your statefile
2. Generate Terraform files within that directory

**ERROR HANDLING**

Right now, the errors should be just the output from Python. Basic Python troubleshooting skills should get your through any issues, as this is a very flat script. Usually, KeyError and IndexError are the only ones, and that's just due to a missing value from within the state


**PLEASE DO NOT:**

Use this script to write all of your Terraform code. Statefiles exist for a reason, and are incredibly durable and useful for managing many resources. This tool is meant mainly for refactoring purposes as a one-off run, not as a running service. That said, it's a free world so please use as you like!
