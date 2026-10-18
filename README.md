# ViShare_Quick

**Version:** `alpha_0.1`  
**Phase:** 1, Build 1: Foundation / Initialisation  
**Platforms:** Windows 11 and Linux  
**Runtime:** Python 3.10+

ViShare_Quick is a cross-platform command-line project intended to become interoperable with Android devices using Google's native Quick Share. This first build is only the project foundation. It does **not** implement Quick Share discovery or file transfer yet.

## Alpha 0.1 scope

- Python package and CLI entry point
- `--help` and `--version`
- Basic environment diagnostics with `doctor`
- Minimal automated tests
- GitHub Actions workflows for tests and tagged Windows/Linux builds
- No runtime third-party dependencies

## Requirements

- Python 3.10 or newer
- Git
- Optional for packaging locally: `pip`

## Run from source

### Windows PowerShell or CMD

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m vishare_quick --help
.\.venv\Scripts\python.exe -m vishare_quick --version
.\.venv\Scripts\python.exe -m vishare_quick doctor
```

### Linux

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m vishare_quick --help
python -m vishare_quick --version
python -m vishare_quick doctor
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

If you installed development dependencies, you can also run:

```bash
pytest
```

## GitHub setup

This ZIP does not initialize or push to GitHub automatically. Review the files first, then run the following from this folder if `ahamviraj/ViShare_Quick` exists and is empty:

```bash
git init
git add .
git commit -m "Initialize ViShare_Quick alpha_0.1 foundation"
git branch -M main
git remote add origin https://github.com/ahamviraj/ViShare_Quick.git
git push -u origin main
```

If the repository already contains commits or files, **clone/pull it first** instead of running `git init` in this folder, to avoid creating unrelated history.

## Create the alpha_0.1 release

After the source has been pushed and tests pass:

```bash
git tag alpha_0.1
git push origin alpha_0.1
```

The GitHub Actions release workflow builds a Windows executable and a Linux executable, then attaches them to a GitHub Release for the tag. In the repository settings, ensure Actions are enabled. The workflow needs `contents: write` permission to publish the release.

The workflow is configured to run on tags matching `alpha_*`, `beta_*`, or `stable_*`. Do not tag a release until you have reviewed and tested that build.

## Planned build sequence

- `alpha_0.1`: Foundation / initialisation (this build)
- `alpha_0.2`: Make the laptop discoverable by Android Quick Share
- `alpha_0.3`: Receive files and save them in `ViShare Quick/download`
- `alpha_0.4`: Discover Android devices running Quick Share
- `alpha_0.5`: Select and send files to an Android Quick Share recipient
- Phase 2: beta releases through `stable_1.0`

These are project goals, not claims that the Quick Share protocol is already implemented. Each milestone must be verified with real devices.

## Security and protocol note

Do not expose this CLI to untrusted networks as a file receiver until authentication, transfer confirmation, and protocol security have been implemented and tested. Alpha 0.1 does not open listening sockets or transfer files.

## License

No license has been selected in this alpha foundation. Add a license after deciding how you want this project and any incorporated dependencies to be licensed.
