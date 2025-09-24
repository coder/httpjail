use std::fs;
use std::io::Write;
use tempfile::{NamedTempFile, TempPath};

/// Helper function to create an executable program file with the given content
pub fn create_program_file(content: &str) -> TempPath {
    let mut program_file = NamedTempFile::new().unwrap();
    program_file.write_all(content.as_bytes()).unwrap();
    program_file.flush().unwrap();

    let program_path = program_file.into_temp_path();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&program_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&program_path, perms).unwrap();
    }

    program_path
}
