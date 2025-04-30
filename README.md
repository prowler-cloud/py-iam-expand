<div align="center">
  <img src="imgs/py-iam-expand.png" alt="py-iam-expand logo" height="300" />
</div>

# py-iam-expand

`py-iam-expand` is a Python tool to expand and deobfuscate AWS IAM actions.

This can help you to understand and analyze AWS IAM policies more effectively.


## Features

*   Expand IAM actions with wildcards (`*`, `?`).
*   Invert IAM action sets to find actions *not* matching specified patterns.
*   Process IAM policies in JSON format.
*   Command-line interface for easy use.
*   Removes whitespaces or other characters used to obfuscate policies.
*   Decide how to handle non valid actions: Raise an error, keep them or remove them.

## Installation

Install `py-iam-expand` using pip:
```
pip install py-iam-expand
```

## Usage

### Command-Line Interface (CLI)

The `py-iam-expand` tool can be used via the command line to expand IAM actions.

#### Basic Expansion

Expand IAM actions from the command line:

```bash
py-iam-expand "s3:Get*"
```

This will output the expanded actions to the console:

```text
s3:GetAccelerateConfiguration
s3:GetAccessGrant
s3:GetAccessGrantsInstance
s3:GetAccessGrantsInstanceForPrefix
s3:GetAccessGrantsInstanceResourcePolicy
...
```

#### Using Standard Input (stdin)

You can pipe IAM action patterns to `py-iam-expand` via stdin:

```bash
echo "s3:Get*Tagging" | py-iam-expand
```

#### Expanding IAM Policies

Expand actions within a JSON IAM policy document:

```bash
py-iam-expand < example_policy.json > expanded_policy.json
```

#### Inverting Actions

Invert a set of actions to find all actions *not* matching the provided patterns:

```bash
py-iam-expand -i s3:Get* ec2:Describe*
```


#### Command-Line Options

```
usage: py-iam-expand [-h] [--version] [-i] [--invalid-action {raise,remove,keep}]
                     [--invalid-notaction {raise,remove,keep}]
                     [ACTION_PATTERN ...]

Expand AWS IAM action patterns provided as arguments/stdin lines OR expand actions within an IAM Policy JSON provided
via stdin.

positional arguments:
  ACTION_PATTERN        IAM action pattern(s) to expand/invert (e.g., 's3:Get*' 'ec2:*'). If omitted, reads from
                        stdin. Cannot be used if stdin is a JSON policy.

optional arguments:
  -h, --help            show this help message and exit
  --version             Show the package version and exit
  -i, --invert          Invert pattern expansion result. Cannot be used if stdin is a JSON policy.
  --invalid-action {raise,remove,keep}
                        How to handle invalid patterns in Action elements: raise - raise an error (default), remove -
                        silently remove invalid patterns, keep - keep invalid patterns in the result
  --invalid-notaction {raise,remove,keep}
                        How to handle invalid patterns in NotAction elements: raise - raise an error, remove -
                        silently remove invalid patterns, keep - keep invalid patterns in the result (default)
```

### Library
This package can be used as library, check examples in [examples](./examples/) folder.

## Running Tests

To run the tests:

```bash
poetry run pytest tests
```

## Data

This project leverages the [`iam-data`](https://github.com/cloud-copilot/iam-data-python) package for up-to-date AWS IAM data.

## Contributing

Contributions are welcome! Please submit pull requests or open issues on GitHub.


## Acknowledgment

This project was inspired by previous projects like [cloud-copilot/iam-expand](https://github.com/cloud-copilot/iam-expand) and [ecdavis/iampoliciesgonewild](https://github.com/ecdavis/iampoliciesgonewild)
