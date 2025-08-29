
# SafeTree

**SafeTree** is an advanced tool for securely managing files and folders. It allows you to clone folders using hard links, maintain versioned copies, encrypt/decrypt files with AES-256, and securely delete files — all while preserving the original structure and minimizing storage usage.

## Features

- Clone files and folders using **hard links** (no extra storage used).  
- Preserve **full folder structures** during clone operations.  
- Create **versioned folder clones** (`Folder_v1`, `Folder_v2`, etc.) to track changes.  
- **AES-256-GCM encryption and decryption** of files.  
- **Secure deletion** with multiple overwrites.  
- **Drag-and-drop support** for files and folders.  
- **Visual tree view** to explore folder structures.  
- **Progress bars** for long operations.  
- **Dark/light mode toggle** for UI preferences.  
- Logs all operations for easy tracking.

## Installation

Requires Python 3.10+ and dependencies:

```bash
pip install PySide6 pycryptodome
````

## Usage

Run the program:

```bash
python main.py
```

* **Clone Folder**: Select a folder to clone its structure and files using hard links.
* **Clone Folder with Version Control**: Clone a folder with automatic versioning.
* **Encrypt Files**: Encrypt selected files with AES-256.
* **Decrypt File**: Decrypt previously encrypted files.
* **Secure Delete**: Permanently delete files with multiple overwrite passes.
* **Drag-and-Drop**: Drop files or folders onto the app to manage them.

## Notes

* Hard links require the source and destination to be on the **same filesystem**.
* AES key is generated per session; to persist encrypted data across sessions, modify key management.
* Secure deletion is best-effort on SSDs due to wear-leveling.

## License

MIT License


