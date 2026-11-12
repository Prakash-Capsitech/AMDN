"""Best-effort pre-tool secret guard shared by Codex and Claude Code.

Never reads files, logs tool inputs, or grants permissions. OS sandboxing is the
security boundary; literal command inspection cannot interpret arbitrary code.
"""
import json
import os
from pathlib import Path
import re
import shlex
import sys

MAX_INPUT = 1_000_000
SECRET_DIRS = {'.ssh', '.aws', '.kube', '.gnupg', '.secrets', 'secrets'}
SECRET_NAMES = {'.netrc', '.npmrc', '.pypirc', '.git-credentials', 'auth.json',
                'credentials.json', 'credentials', 'kubeconfig', 'id_rsa',
                'id_ed25519', 'id_ecdsa', 'terraform.tfstate'}
SECRET_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.keystore', '.tfstate'}
PATH_KEYS = {'path', 'file_path', 'filePath', 'directory', 'notebook_path',
             'target_file', 'filename', 'paths', 'files'}


def sensitive_path(value, cwd):
    if not isinstance(value, str) or not value or '://' in value:
        return False
    # resolve checks symlink targets, but does not open/read the target file.
    candidate = Path(os.path.expandvars(os.path.expanduser(value)))
    if not candidate.is_absolute():
        candidate = cwd / candidate
    paths = [candidate, candidate.resolve(strict=False)]
    for path in paths:
        parts = path.parts
        name = path.name
        if any(part in SECRET_DIRS for part in parts):
            return True
        if name == '.env' or (name.startswith('.env.') and name != '.env.example'):
            return True
        if name in SECRET_NAMES or path.suffix.lower() in SECRET_SUFFIXES:
            return True
        if any(parts[i:i + 2] in [('.config', 'gh'), ('.config', 'gcloud')]
               for i in range(len(parts) - 1)):
            return True
        if name == 'config.json' and '.docker' in parts:
            return True
        if 'proc' in parts and name == 'environ':
            return True
    return False


def path_arguments(value, key=''):
    if isinstance(value, dict):
        for child_key, child in value.items():
            yield from path_arguments(child, child_key)
    elif isinstance(value, list):
        for child in value:
            yield from path_arguments(child, key)
    elif isinstance(value, str) and (key in PATH_KEYS or key.endswith('_path')):
        yield value


def blocked_command(command, cwd):
    # Catch common credential-printing routes. Not a shell parser or DLP engine.
    if re.search(r'\bgh\s+auth\s+token\b|\bgit\s+credential\s+fill\b', command):
        return True
    if re.search(r'\b(printenv|env|set|export|declare)\s*(?:-[p0]+\s*)?(?:$|[;|&])', command):
        return True
    if re.search(r'\b(os\.environ|process\.env)\b|/proc/[^\s]+/environ', command):
        return True
    if re.search(r'\$(?:\{)?[A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z_]*', command):
        return True
    try:
        tokens = shlex.split(command, comments=False)
    except ValueError:
        return True
    for token in tokens:
        # Inline scripts and quoted strings can contain literal protected paths.
        for part in re.split(r'''[\s;|&<>"'`(){}\[\],=]+''', token):
            if sensitive_path(part.lstrip('@'), cwd):
                return True
    return False


def blocked(event):
    if not isinstance(event, dict) or event.get('hook_event_name') != 'PreToolUse':
        return True
    tool = event.get('tool_name')
    args = event.get('tool_input')
    if not isinstance(tool, str) or not isinstance(args, dict):
        return True
    cwd = Path(event.get('cwd') or Path.cwd())
    if any(sensitive_path(path, cwd) for path in path_arguments(args)):
        return True
    if tool in {'Bash', 'exec_command', 'shell', 'shell_command'}:
        command = args.get('command', args.get('cmd'))
        if isinstance(command, list):
            command = shlex.join(command)
        return not isinstance(command, str) or blocked_command(command, cwd)
    if tool == 'apply_patch':
        patch = args.get('command', args.get('patch', args.get('input')))
        if not isinstance(patch, str):
            return True
        return any(sensitive_path(path, cwd) for path in re.findall(
            r'^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$', patch, re.M))
    return False


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        denied = len(raw) > MAX_INPUT or blocked(json.loads(raw))
    except Exception:
        # Do not echo malformed input or exception details: they may contain secrets.
        denied = True
    if denied:
        print(json.dumps({'hookSpecificOutput': {
            'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',
            'permissionDecisionReason': 'AMDN secret guard blocked a sensitive or uninspectable request. Use a sanitized fixture; do not print credentials.'}}))
    # Empty successful output leaves the agent's normal permission checks intact.


if __name__ == '__main__':
    main()
