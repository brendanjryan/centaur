import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("configure_git_signing.sh")


class ConfigureGitSigningTests(unittest.TestCase):
    def run_script(self, root: Path, **environment: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "GNUPGHOME": str(root / "gnupg"),
                "GIT_CONFIG_GLOBAL": str(root / "gitconfig"),
                **environment,
            }
        )
        return subprocess.run(
            [str(SCRIPT)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_disabled_is_a_noop(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.run_script(root)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "gnupg").exists())

    def test_enabled_requires_a_readable_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.run_script(
                root,
                CENTAUR_GIT_COMMIT_SIGNING_ENABLED="true",
                CENTAUR_GIT_COMMIT_SIGNING_KEY_PATH=str(root / "missing.asc"),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not readable", result.stderr)

    def test_rejects_an_invalid_enabled_value(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_script(
                Path(temp), CENTAUR_GIT_COMMIT_SIGNING_ENABLED="sometimes"
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid CENTAUR_GIT_COMMIT_SIGNING_ENABLED", result.stderr)

    def test_imports_key_and_signs_commits(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source_home = root / "source-gnupg"
            source_home.mkdir(mode=0o700)
            source_env = {**os.environ, "GNUPGHOME": str(source_home)}
            subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-generate-key",
                    "Centaur Test <centaur-test@example.com>",
                    "ed25519",
                    "sign",
                    "0",
                ],
                env=source_env,
                check=True,
                capture_output=True,
            )
            key_path = root / "private-key.asc"
            with key_path.open("wb") as key_file:
                subprocess.run(
                    ["gpg", "--batch", "--armor", "--export-secret-keys"],
                    env=source_env,
                    check=True,
                    stdout=key_file,
                    stderr=subprocess.PIPE,
                )

            result = self.run_script(
                root,
                CENTAUR_GIT_COMMIT_SIGNING_ENABLED="true",
                CENTAUR_GIT_COMMIT_SIGNING_KEY_PATH=str(key_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            git_env = {
                **os.environ,
                "GNUPGHOME": str(root / "gnupg"),
                "GIT_CONFIG_GLOBAL": str(root / "gitconfig"),
            }
            repository = root / "repository"
            subprocess.run(["git", "init", "-q", str(repository)], env=git_env, check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "Centaur Test"],
                env=git_env,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "user.email",
                    "centaur-test@example.com",
                ],
                env=git_env,
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "--allow-empty", "-m", "test"],
                env=git_env,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "verify-commit", "HEAD"],
                env=git_env,
                check=True,
                capture_output=True,
            )


if __name__ == "__main__":
    unittest.main()
