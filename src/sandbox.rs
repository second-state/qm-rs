//! The scope's durable computer.
//!
//! Each scope gets a directory that persists across turns: anything the agent
//! writes or installs stays. `execute` runs shell commands there; `read` and
//! `write` work on paths relative to it.
//!
//! The security property this module owns is **confinement**: every path the
//! agent names resolves inside the scope's root, or the call fails. Command
//! policy is enforced a layer up, in [`crate::tools`], because it needs the
//! resolution and the approval store.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::error::{AppError, AppResult};
use crate::types::{GrantedHandle, LayerMode, ScopeId, WorkspaceLayer};

/// Result of running a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
    pub timed_out: bool,
    /// Set when output was truncated to the configured cap.
    pub truncated: bool,
}

impl ExecResult {
    /// The single string handed back to the model.
    pub fn render(&self) -> String {
        let mut out = String::new();
        if !self.stdout.is_empty() {
            out.push_str(&self.stdout);
        }
        if !self.stderr.is_empty() {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str("[stderr]\n");
            out.push_str(&self.stderr);
        }
        if self.timed_out {
            out.push_str("\n[timed out]");
        } else if self.code != 0 {
            out.push_str(&format!("\n[exit {}]", self.code));
        }
        if self.truncated {
            out.push_str("\n[output truncated]");
        }
        if out.trim().is_empty() {
            out = "[no output]".to_string();
        }
        out
    }
}

/// The substrate seam. A different backend — a container, a microVM — swaps in
/// here without touching the tool surface.
#[async_trait::async_trait]
pub trait Sandbox: Send + Sync {
    async fn exec(
        &self,
        scope: &ScopeId,
        command: &str,
        env: &[(String, String)],
    ) -> AppResult<ExecResult>;
    fn read(&self, scope: &ScopeId, path: &str) -> AppResult<String>;
    fn write(&self, scope: &ScopeId, path: &str, content: &str) -> AppResult<()>;
    fn list(&self, scope: &ScopeId, path: &str) -> AppResult<Vec<String>>;
    fn remove(&self, scope: &ScopeId, path: &str) -> AppResult<bool>;
    /// Materialize the turn's layers and granted handles into the workspace.
    fn provision(
        &self,
        scope: &ScopeId,
        layers: &[WorkspaceLayer],
        handles: &[GrantedHandle],
    ) -> AppResult<()>;
    fn root_of(&self, scope: &ScopeId) -> PathBuf;
}

/// The local-filesystem sandbox: a directory per scope on this machine.
///
/// Isolation here is path confinement, not kernel-level. Commands run as the
/// server's own user, so a scope's `execute` can reach anything that user can.
/// That is the same trade upstream makes for its local sandbox backend, and it
/// is why the command policy is not optional.
pub struct LocalSandbox {
    root_dir: PathBuf,
    exec_timeout: Duration,
    max_output_bytes: usize,
}

impl LocalSandbox {
    pub fn new(root_dir: PathBuf, exec_timeout_secs: u64, max_output_bytes: usize) -> Self {
        Self {
            root_dir,
            exec_timeout: Duration::from_secs(exec_timeout_secs.max(1)),
            max_output_bytes: max_output_bytes.max(1_000),
        }
    }

    /// Directory name for a scope: `personal:u1` → `personal__u1`, with
    /// anything outside the safe alphabet replaced so a crafted scope ref
    /// cannot climb out of `root_dir`.
    fn scope_dir_name(scope: &ScopeId) -> String {
        let mut out = String::with_capacity(scope.as_str().len());
        for c in scope.as_str().chars() {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                out.push(c);
            } else {
                out.push('_');
            }
        }
        if out.is_empty() {
            out.push_str("unscoped");
        }
        out
    }

    fn ensure_root(&self, scope: &ScopeId) -> AppResult<PathBuf> {
        let root = self.root_of(scope);
        std::fs::create_dir_all(root.join("workspace"))?;
        Ok(root)
    }

    /// Resolve an agent-supplied path inside the scope root.
    ///
    /// Rejects absolute paths and any `..` component *before* touching the
    /// filesystem, then verifies the resolved result really is under the root —
    /// which is what catches a symlink planted by an earlier turn pointing out
    /// of the sandbox.
    fn resolve(&self, scope: &ScopeId, path: &str) -> AppResult<PathBuf> {
        let requested = Path::new(path);
        if requested.is_absolute() {
            return Err(AppError::forbidden(format!(
                "path {path:?} is absolute; use a path relative to your workspace"
            )));
        }
        let mut relative = PathBuf::new();
        for component in requested.components() {
            match component {
                Component::Normal(part) => relative.push(part),
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(AppError::forbidden(format!(
                        "path {path:?} escapes the workspace"
                    )))
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(AppError::forbidden(format!(
                        "path {path:?} is not relative"
                    )))
                }
            }
        }

        let root = self.ensure_root(scope)?;
        let canonical_root = root.canonicalize()?;
        let target = canonical_root.join(&relative);

        // Canonicalize the deepest existing ancestor: the target itself may not
        // exist yet on a write, but every existing part of the path must stay
        // inside the root once symlinks are followed.
        let mut probe = target.clone();
        loop {
            match probe.canonicalize() {
                Ok(resolved) => {
                    if !resolved.starts_with(&canonical_root) {
                        return Err(AppError::forbidden(format!(
                            "path {path:?} resolves outside the workspace"
                        )));
                    }
                    break;
                }
                Err(_) => match probe.parent() {
                    Some(parent)
                        if parent.starts_with(&canonical_root) || parent == canonical_root =>
                    {
                        probe = parent.to_path_buf();
                    }
                    _ => break,
                },
            }
        }
        Ok(target)
    }

    fn cap(&self, mut text: String) -> (String, bool) {
        if text.len() <= self.max_output_bytes {
            return (text, false);
        }
        // Keep the tail: errors and results land at the end of a command's
        // output far more often than the start.
        let start = text.len() - self.max_output_bytes;
        let start = (start..text.len())
            .find(|i| text.is_char_boundary(*i))
            .unwrap_or(text.len());
        text = text.split_off(start);
        (text, true)
    }
}

#[async_trait::async_trait]
impl Sandbox for LocalSandbox {
    fn root_of(&self, scope: &ScopeId) -> PathBuf {
        self.root_dir.join(Self::scope_dir_name(scope))
    }

    async fn exec(
        &self,
        scope: &ScopeId,
        command: &str,
        env: &[(String, String)],
    ) -> AppResult<ExecResult> {
        let root = self.ensure_root(scope)?;
        let workspace = root.join("workspace");

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(command)
            .current_dir(&workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        // A deliberately spare environment: the server's own variables are not
        // the scope's to read. Only the keychain the resolution materialized,
        // plus what a shell needs to function.
        cmd.env_clear();
        cmd.env("HOME", &root);
        cmd.env("PWD", &workspace);
        cmd.env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
        );
        cmd.env("QM_SCOPE", scope.as_str());
        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| AppError::internal(format!("failed to start a shell: {e}")))?;
        let mut stdout_pipe = child.stdout.take().expect("piped stdout");
        let mut stderr_pipe = child.stderr.take().expect("piped stderr");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let collect = async {
            let (a, b) = tokio::join!(
                stdout_pipe.read_to_end(&mut stdout),
                stderr_pipe.read_to_end(&mut stderr)
            );
            a?;
            b?;
            child.wait().await
        };

        match timeout(self.exec_timeout, collect).await {
            Ok(status) => {
                let status = status?;
                let (stdout, t1) = self.cap(String::from_utf8_lossy(&stdout).into_owned());
                let (stderr, t2) = self.cap(String::from_utf8_lossy(&stderr).into_owned());
                Ok(ExecResult {
                    stdout,
                    stderr,
                    code: status.code().unwrap_or(-1),
                    timed_out: false,
                    truncated: t1 || t2,
                })
            }
            // `kill_on_drop` reaps the child as the command goes out of scope.
            Err(_) => Ok(ExecResult {
                stdout: String::new(),
                stderr: String::new(),
                code: -1,
                timed_out: true,
                truncated: false,
            }),
        }
    }

    fn read(&self, scope: &ScopeId, path: &str) -> AppResult<String> {
        let target = self.resolve(scope, path)?;
        if !target.exists() {
            return Err(AppError::not_found(format!("{path} (in {scope})")));
        }
        std::fs::read_to_string(&target)
            .map_err(|e| AppError::bad_request(format!("could not read {path}: {e}")))
    }

    fn write(&self, scope: &ScopeId, path: &str, content: &str) -> AppResult<()> {
        let target = self.resolve(scope, path)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, content)?;
        Ok(())
    }

    fn list(&self, scope: &ScopeId, path: &str) -> AppResult<Vec<String>> {
        let target = self.resolve(scope, path)?;
        if !target.is_dir() {
            return Err(AppError::not_found(format!("{path} is not a directory")));
        }
        let mut names: Vec<String> = std::fs::read_dir(&target)?
            .filter_map(Result::ok)
            .map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                if entry.path().is_dir() {
                    format!("{name}/")
                } else {
                    name
                }
            })
            .collect();
        names.sort();
        Ok(names)
    }

    fn remove(&self, scope: &ScopeId, path: &str) -> AppResult<bool> {
        let target = self.resolve(scope, path)?;
        if !target.exists() {
            return Ok(false);
        }
        if target.is_dir() {
            std::fs::remove_dir_all(&target)?;
        } else {
            std::fs::remove_file(&target)?;
        }
        Ok(true)
    }

    /// Create the layer mount points and write a manifest of shared handles.
    ///
    /// Read-only layers and granted handles are materialized as directories the
    /// tool surface copies into on demand rather than as symlinks, so a stray
    /// `rm -rf` inside the sandbox cannot follow a link into another scope's
    /// real files.
    fn provision(
        &self,
        scope: &ScopeId,
        layers: &[WorkspaceLayer],
        handles: &[GrantedHandle],
    ) -> AppResult<()> {
        let root = self.ensure_root(scope)?;
        for layer in layers {
            if layer.mode == LayerMode::Ro {
                std::fs::create_dir_all(root.join(&layer.mount_path))?;
            }
        }
        if handles.is_empty() {
            return Ok(());
        }
        let shared = root.join("shared");
        std::fs::create_dir_all(&shared)?;
        let manifest: Vec<String> = handles
            .iter()
            .map(|h| {
                format!(
                    "{}\t{}\t{}\t{}",
                    h.handle_path,
                    h.owner_scope_id,
                    h.owner_path,
                    h.permission.as_str()
                )
            })
            .collect();
        std::fs::write(shared.join(".handles"), manifest.join("\n"))?;
        Ok(())
    }
}

/// Keychain values as a process environment, with anything unusable dropped.
pub fn env_from_keychain(entries: &[(String, String)]) -> Vec<(String, String)> {
    let mut seen: HashMap<&str, ()> = HashMap::new();
    entries
        .iter()
        .filter(|(k, v)| {
            // A NUL cannot cross the exec boundary, and a duplicate key would
            // silently pick one value.
            !k.contains('\0') && !v.contains('\0') && seen.insert(k.as_str(), ()).is_none()
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Permission;

    fn sandbox() -> (LocalSandbox, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (LocalSandbox::new(dir.path().to_path_buf(), 10, 32_000), dir)
    }

    fn scope() -> ScopeId {
        ScopeId::personal("u1")
    }

    #[test]
    fn files_round_trip_within_a_scope() {
        let (s, _dir) = sandbox();
        s.write(&scope(), "workspace/notes.md", "hello").unwrap();
        assert_eq!(s.read(&scope(), "workspace/notes.md").unwrap(), "hello");
        assert!(s
            .list(&scope(), "workspace")
            .unwrap()
            .contains(&"notes.md".to_string()));
        assert!(s.remove(&scope(), "workspace/notes.md").unwrap());
        assert!(!s.remove(&scope(), "workspace/notes.md").unwrap());
    }

    #[test]
    fn scopes_cannot_see_each_others_files() {
        let (s, _dir) = sandbox();
        s.write(&scope(), "workspace/secret.md", "mine").unwrap();
        assert!(matches!(
            s.read(&ScopeId::personal("u2"), "workspace/secret.md"),
            Err(AppError::NotFound(_))
        ));
    }

    #[test]
    fn traversal_out_of_the_workspace_is_refused() {
        let (s, _dir) = sandbox();
        for bad in [
            "../escape.txt",
            "workspace/../../escape.txt",
            "/etc/passwd",
            "workspace/../../../tmp/x",
            "./../../x",
        ] {
            let err = s.write(&scope(), bad, "x").unwrap_err();
            assert!(
                matches!(err, AppError::Forbidden(_)),
                "{bad:?} should be forbidden, got {err:?}"
            );
            assert!(matches!(s.read(&scope(), bad), Err(AppError::Forbidden(_))));
        }
    }

    #[test]
    fn a_dot_prefixed_path_still_resolves_inside() {
        let (s, _dir) = sandbox();
        s.write(&scope(), "./workspace/a.txt", "x").unwrap();
        assert_eq!(s.read(&scope(), "workspace/a.txt").unwrap(), "x");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_pointing_out_of_the_sandbox_is_refused() {
        let (s, dir) = sandbox();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "not yours").unwrap();

        // Plant the link as an earlier turn's `execute` could have.
        let root = s.root_of(&scope());
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("workspace/link.txt")).unwrap();

        let err = s.read(&scope(), "workspace/link.txt").unwrap_err();
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "a symlink out of the sandbox must not be followed, got {err:?}"
        );
    }

    #[test]
    fn odd_scope_refs_cannot_climb_out_of_the_sandbox_root() {
        let (s, dir) = sandbox();
        let hostile = ScopeId::from_raw("personal:../../etc");
        let root = s.root_of(&hostile);
        assert!(
            root.starts_with(dir.path()),
            "scope directory escaped the root: {root:?}"
        );
        assert!(!root.to_string_lossy().contains(".."));
    }

    #[test]
    fn reading_a_missing_file_is_not_found_not_an_io_error() {
        let (s, _dir) = sandbox();
        assert!(matches!(
            s.read(&scope(), "workspace/nope.md"),
            Err(AppError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn execute_runs_in_the_scope_workspace() {
        let (s, _dir) = sandbox();
        s.write(&scope(), "workspace/hello.txt", "hi").unwrap();
        let result = s.exec(&scope(), "ls", &[]).await.unwrap();
        assert_eq!(result.code, 0);
        assert!(result.stdout.contains("hello.txt"));
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn execute_reports_a_non_zero_exit_and_stderr() {
        let (s, _dir) = sandbox();
        let result = s
            .exec(&scope(), "echo oops >&2; exit 3", &[])
            .await
            .unwrap();
        assert_eq!(result.code, 3);
        assert!(result.stderr.contains("oops"));
        let rendered = result.render();
        assert!(rendered.contains("[stderr]"));
        assert!(rendered.contains("[exit 3]"));
    }

    #[tokio::test]
    async fn execute_times_out_rather_than_hanging_the_turn() {
        let dir = tempfile::tempdir().unwrap();
        let s = LocalSandbox::new(dir.path().to_path_buf(), 1, 32_000);
        let result = s.exec(&scope(), "sleep 30", &[]).await.unwrap();
        assert!(result.timed_out);
        assert!(result.render().contains("[timed out]"));
    }

    #[tokio::test]
    async fn only_the_supplied_keychain_reaches_the_command() {
        let (s, _dir) = sandbox();
        std::env::set_var("QM_SANDBOX_LEAK_CHECK", "leaked");
        let result = s
            .exec(
                &scope(),
                "echo \"key=$MY_KEY leak=$QM_SANDBOX_LEAK_CHECK scope=$QM_SCOPE\"",
                &[("MY_KEY".to_string(), "value".to_string())],
            )
            .await
            .unwrap();
        std::env::remove_var("QM_SANDBOX_LEAK_CHECK");

        assert!(result.stdout.contains("key=value"));
        assert!(
            result.stdout.contains("leak= "),
            "the server's own environment must not leak into a scope: {:?}",
            result.stdout
        );
        assert!(result.stdout.contains("scope=personal:u1"));
    }

    #[tokio::test]
    async fn long_output_is_truncated_to_the_tail() {
        let dir = tempfile::tempdir().unwrap();
        let s = LocalSandbox::new(dir.path().to_path_buf(), 10, 1_000);
        let result = s
            .exec(
                &scope(),
                "for i in $(seq 1 5000); do echo linenumber$i; done",
                &[],
            )
            .await
            .unwrap();
        assert!(result.truncated);
        assert!(result.stdout.len() <= 1_100);
        assert!(
            result.stdout.contains("linenumber5000"),
            "the tail is what matters"
        );
        assert!(result.render().contains("[output truncated]"));
    }

    #[tokio::test]
    async fn a_command_with_no_output_still_renders_something() {
        let (s, _dir) = sandbox();
        let result = s.exec(&scope(), "true", &[]).await.unwrap();
        assert_eq!(result.render(), "[no output]");
    }

    #[test]
    fn provisioning_creates_read_only_mounts_and_a_handle_manifest() {
        let (s, _dir) = sandbox();
        let layers = vec![
            WorkspaceLayer {
                scope_id: ScopeId::org("acme"),
                mount_path: "org".into(),
                mode: LayerMode::Ro,
            },
            WorkspaceLayer {
                scope_id: scope(),
                mount_path: "workspace".into(),
                mode: LayerMode::Rw,
            },
        ];
        let handles = vec![GrantedHandle {
            handle_path: "shared/plan.md".into(),
            owner_scope_id: ScopeId::personal("u2"),
            owner_path: "notes/plan.md".into(),
            permission: Permission::Read,
        }];
        s.provision(&scope(), &layers, &handles).unwrap();

        assert!(s.root_of(&scope()).join("org").is_dir());
        let manifest = s.read(&scope(), "shared/.handles").unwrap();
        assert!(manifest.contains("shared/plan.md"));
        assert!(manifest.contains("personal:u2"));
        assert!(manifest.contains("read"));
    }

    #[test]
    fn keychain_env_drops_nuls_and_duplicate_keys() {
        let entries = vec![
            ("A".to_string(), "1".to_string()),
            ("A".to_string(), "2".to_string()),
            ("B\0AD".to_string(), "x".to_string()),
            ("C".to_string(), "with\0nul".to_string()),
        ];
        let env = env_from_keychain(&entries);
        assert_eq!(env, vec![("A".to_string(), "1".to_string())]);
    }
}
