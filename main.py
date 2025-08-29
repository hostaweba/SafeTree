#!/usr/bin/env python3
"""
Advanced File & Folder Manager (PySide6)

Features:
- Manual file hard-linking + timestamped backup
- Folder clone using hard links, preserving full structure
- Folder clone with version control (Source_v1, Source_v2, ...)
- AES-256-GCM encryption/decryption (manual)
- Secure deletion (multiple overwrite passes)
- Drag & drop support for files/folders
- Progress bars for long operations (clone/encrypt)
- Visual tree view for folder structure
- Restore version option
- Dark/Light mode toggle
- GUI + file logging
"""

import sys
import os
import shutil
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Optional

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog,
    QTextEdit, QTreeWidget, QTreeWidgetItem, QProgressBar, QCheckBox, QSplitter,
    QLabel, QMessageBox, QInputDialog, QSizePolicy
)
from PySide6.QtGui import QFont, Qt, QDragEnterEvent, QDropEvent, QIcon
from PySide6.QtCore import QThread, Signal

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ----------------------
# Configuration & Paths
# ----------------------
BACKUP_DIR = Path("file_backups")
LOG_FILE = Path("file_secure.log")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
if not LOG_FILE.exists():
    LOG_FILE.write_text("")  # create

# ----------------------
# Worker Threads
# ----------------------
class FolderCloneThread(QThread):
    """Clone a folder (exact structure) into destination/<source.name>/... using hard links."""
    progress = Signal(int)            # 0-100
    log_signal = Signal(str)
    finished_signal = Signal(Path)

    def __init__(self, source: Path, destination_parent: Path, preserve_name: bool = True):
        super().__init__()
        self.source = source
        self.dest_parent = destination_parent
        self.preserve_name = preserve_name

    def run(self):
        try:
            files = [p for p in self.source.rglob("*") if p.is_file()]
            total = len(files) or 1
            counter = 0

            # destination root: dest_parent / source.name
            target_root = self.dest_parent / (self.source.name if self.preserve_name else "")
            if str(target_root).endswith(os.sep) or str(target_root) == "":
                # guard (shouldn't happen)
                target_root = self.dest_parent / self.source.name
            target_root.mkdir(parents=True, exist_ok=True)
            self.log_signal.emit(f"Cloning {self.source} → {target_root}")

            for file in files:
                rel = file.relative_to(self.source)
                tgt = target_root / rel
                tgt.parent.mkdir(parents=True, exist_ok=True)
                try:
                    if not tgt.exists():
                        os.link(file, tgt)
                        self.log_signal.emit(f"Hard-linked: {tgt}")
                    else:
                        self.log_signal.emit(f"Already exists (skipped): {tgt}")
                except Exception as e:
                    self.log_signal.emit(f"Link error: {file} → {tgt} : {e}")
                counter += 1
                self.progress.emit(int(counter / total * 100))

            self.progress.emit(100)
            self.log_signal.emit("Folder clone complete.")
            self.finished_signal.emit(target_root)
        except Exception as e:
            self.log_signal.emit(f"FolderCloneThread failed: {e}")
            self.progress.emit(0)
            self.finished_signal.emit(Path(""))

class FolderCloneVersionThread(QThread):
    """Create a versioned clone: dest_parent / Source_vN / ... (hard links)."""
    progress = Signal(int)
    log_signal = Signal(str)
    finished_signal = Signal(Path)

    def __init__(self, source: Path, destination_parent: Path):
        super().__init__()
        self.source = source
        self.dest_parent = destination_parent

    def determine_next_version(self, base_name: str) -> int:
        existing = [p.name for p in self.dest_parent.iterdir() if p.is_dir() and p.name.startswith(base_name)]
        v = 1
        while f"{base_name}_v{v}" in existing:
            v += 1
        return v

    def run(self):
        try:
            base = self.source.name
            v = self.determine_next_version(base)
            versioned = self.dest_parent / f"{base}_v{v}"
            versioned.mkdir(parents=True, exist_ok=True)
            self.log_signal.emit(f"Creating versioned clone: {versioned}")

            files = [p for p in self.source.rglob("*") if p.is_file()]
            total = len(files) or 1
            counter = 0

            for file in files:
                rel = file.relative_to(self.source)
                tgt = versioned / rel
                tgt.parent.mkdir(parents=True, exist_ok=True)
                try:
                    if not tgt.exists():
                        os.link(file, tgt)
                        self.log_signal.emit(f"Hard-linked: {tgt}")
                except Exception as e:
                    self.log_signal.emit(f"Link error: {file} → {tgt} : {e}")
                counter += 1
                self.progress.emit(int(counter / total * 100))

            self.progress.emit(100)
            self.log_signal.emit(f"Versioned clone complete: {versioned}")
            self.finished_signal.emit(versioned)
        except Exception as e:
            self.log_signal.emit(f"FolderCloneVersionThread failed: {e}")
            self.progress.emit(0)
            self.finished_signal.emit(Path(""))

class FileEncryptThread(QThread):
    progress = Signal(int)
    log_signal = Signal(str)
    finished_signal = Signal(list)

    def __init__(self, files: List[Path], key: bytes):
        super().__init__()
        self.files = files
        self.key = key

    def run(self):
        results = []
        total = len(self.files) or 1
        for idx, fpath in enumerate(self.files):
            try:
                enc_path = fpath.with_suffix(fpath.suffix + ".enc")
                cipher = AES.new(self.key, AES.MODE_GCM)
                with open(fpath, "rb") as rf:
                    plaintext = rf.read()
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                with open(enc_path, "wb") as wf:
                    wf.write(cipher.nonce + tag + ciphertext)
                self.log_signal.emit(f"Encrypted: {enc_path}")
                results.append(enc_path)
            except Exception as e:
                self.log_signal.emit(f"Encrypt error {fpath}: {e}")
            self.progress.emit(int((idx + 1) / total * 100))
        self.progress.emit(100)
        self.log_signal.emit("Encryption finished.")
        self.finished_signal.emit(results)

# ----------------------
# Utility functions
# ----------------------
def now_str(fmt="%Y%m%d%H%M%S") -> str:
    return datetime.now().strftime(fmt)

def sha256_of(file: Path) -> str:
    h = hashlib.sha256()
    with open(file, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def log_to_file(message: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {message}\n")

# ----------------------
# Main GUI Application
# ----------------------
class AdvancedFileManager(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced File & Folder Manager")
        self.setWindowIcon(QIcon())  # can set a path to an icon if desired
        self.resize(1100, 720)
        self.setAcceptDrops(True)

        # AES key (random for this session). In a real app you'd manage keys securely.
        self.key = get_random_bytes(32)

        # UI state
        self.dark_mode = True
        self.apply_style()

        # Layouts
        main_layout = QVBoxLayout(self)
        self.setLayout(main_layout)

        # Header / Info row
        header_layout = QHBoxLayout()
        title = QLabel("⚙️ Advanced File & Folder Manager")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        header_layout.addWidget(title)
        header_layout.addStretch()
        self.mode_button = QPushButton("Toggle Light Mode")
        self.mode_button.clicked.connect(self.toggle_mode)
        header_layout.addWidget(self.mode_button)
        main_layout.addLayout(header_layout)

        # Buttons (grouped)
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        # File actions
        self.btn_file_link = QPushButton("Hard Link File / Backup")
        self.btn_file_link.clicked.connect(self.select_file_for_link)
        btn_layout.addWidget(self.btn_file_link)

        self.btn_encrypt = QPushButton("Encrypt Files")
        self.btn_encrypt.clicked.connect(self.select_files_for_encrypt)
        btn_layout.addWidget(self.btn_encrypt)

        self.btn_decrypt = QPushButton("Decrypt File")
        self.btn_decrypt.clicked.connect(self.select_file_for_decrypt)
        btn_layout.addWidget(self.btn_decrypt)

        self.btn_secure_delete = QPushButton("Secure Delete File")
        self.btn_secure_delete.clicked.connect(self.select_file_for_secure_delete)
        btn_layout.addWidget(self.btn_secure_delete)

        # Folder actions
        self.btn_clone = QPushButton("Clone Folder Structure")
        self.btn_clone.clicked.connect(self.select_folder_for_clone)
        btn_layout.addWidget(self.btn_clone)

        self.btn_clone_version = QPushButton("Clone Folder with Version Control")
        self.btn_clone_version.clicked.connect(self.select_folder_for_version_clone)
        btn_layout.addWidget(self.btn_clone_version)

        self.btn_restore_version = QPushButton("Restore Version (from dest)")
        self.btn_restore_version.clicked.connect(self.restore_version_dialog)
        btn_layout.addWidget(self.btn_restore_version)

        main_layout.addLayout(btn_layout)

        # Splitter: left = tree view, right = logs
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left side: Tree view + controls
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_widget.setLayout(left_layout)

        tree_label = QLabel("Folder Structure (drop a folder to view)")
        tree_label.setFont(QFont("Segoe UI", 11))
        left_layout.addWidget(tree_label)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Folder")
        left_layout.addWidget(self.tree, 1)

        # Small controls under tree
        tree_controls = QHBoxLayout()
        self.btn_refresh_tree = QPushButton("Refresh Tree")
        self.btn_refresh_tree.clicked.connect(self.refresh_tree_selection)
        tree_controls.addWidget(self.btn_refresh_tree)

        self.btn_open_selected = QPushButton("Open Selected Folder")
        self.btn_open_selected.clicked.connect(self.open_selected_in_explorer)
        tree_controls.addWidget(self.btn_open_selected)

        self.hash_checkbox = QCheckBox("Verify SHA-256 before operations")
        tree_controls.addWidget(self.hash_checkbox)
        tree_controls.addStretch()
        left_layout.addLayout(tree_controls)

        splitter.addWidget(left_widget)

        # Right side: Logs + progress
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_widget.setLayout(right_layout)

        log_label = QLabel("Activity Log")
        log_label.setFont(QFont("Segoe UI", 11))
        right_layout.addWidget(log_label)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 10))
        right_layout.addWidget(self.log_view, 1)

        # Progress bar and status
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        right_layout.addWidget(self.progress)

        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        main_layout.addWidget(splitter, 1)

        # Footer: quick info & backup path
        footer_layout = QHBoxLayout()
        self.status_label = QLabel(f"Backups: {BACKUP_DIR.resolve()}")
        footer_layout.addWidget(self.status_label)
        footer_layout.addStretch()
        main_layout.addLayout(footer_layout)

        # Thread placeholders
        self.current_clone_thread: Optional[QThread] = None
        self.current_encrypt_thread: Optional[QThread] = None

        # Seed log with session start
        self.log("Application started.")

    # ----------------------
    # Utilities / Logging
    # ----------------------
    def log(self, message: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {message}"
        self.log_view.append(line)
        log_to_file(message)

    # ----------------------
    # Drag & Drop support
    # ----------------------
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            p = Path(url.toLocalFile())
            if p.exists():
                if p.is_file():
                    # For files: offer to hard link / backup or encrypt via UI button
                    self.log(f"Dropped file: {p}")
                    self.highlight_and_select_file(p)
                elif p.is_dir():
                    self.log(f"Dropped folder: {p}")
                    self.populate_tree(p)
        event.acceptProposedAction()

    def highlight_and_select_file(self, file_path: Path):
        # Quick action dialog: ask what to do (link/backup/encrypt)
        choice, ok = QInputDialog.getItem(self, "File dropped", f"Choose action for {file_path.name}",
                                          ["Hard link & backup", "Encrypt", "Secure delete", "Cancel"], 0, False)
        if not ok or choice == "Cancel":
            return
        if choice == "Hard link & backup":
            self.manual_file_link_and_backup(file_path)
        elif choice == "Encrypt":
            self.start_encrypt_files([file_path])
        elif choice == "Secure delete":
            self.secure_delete(file_path)

    # ----------------------
    # Tree view functions
    # ----------------------
    def populate_tree(self, folder: Path):
        """Populate tree view with folder contents (recursively)."""
        if not folder.exists() or not folder.is_dir():
            QMessageBox.warning(self, "Invalid folder", "Selected path is not a folder.")
            return
        self.tree.clear()
        root = QTreeWidgetItem([folder.name])
        root.setData(0, Qt.UserRole, str(folder))
        self.tree.addTopLevelItem(root)
        self._populate_tree_rec(folder, root)
        self.tree.expandAll()
        self.log(f"Loaded tree view for: {folder}")

    def _populate_tree_rec(self, folder: Path, parent_item: QTreeWidgetItem):
        try:
            for p in sorted(folder.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                child = QTreeWidgetItem([p.name])
                child.setData(0, Qt.UserRole, str(p))
                parent_item.addChild(child)
                if p.is_dir():
                    self._populate_tree_rec(p, child)
        except PermissionError:
            self.log(f"PermissionError while listing {folder}")

    def refresh_tree_selection(self):
        sel = self.tree.currentItem()
        if not sel:
            QMessageBox.information(self, "Select folder", "Select a node in the tree to refresh.")
            return
        path = Path(sel.data(0, Qt.UserRole))
        if path.exists() and path.is_dir():
            parent = sel.parent() or sel  # refresh at that node level
            sel.takeChildren()
            self._populate_tree_rec(path, sel)
            self.tree.expandAll()
            self.log(f"Refreshed: {path}")

    def open_selected_in_explorer(self):
        sel = self.tree.currentItem()
        if not sel:
            QMessageBox.information(self, "Select folder", "Select a node in the tree to open.")
            return
        path = Path(sel.data(0, Qt.UserRole))
        if path.exists():
            if sys.platform.startswith("win"):
                os.startfile(path)
            elif sys.platform.startswith("darwin"):
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
            self.log(f"Opened in file manager: {path}")
        else:
            QMessageBox.warning(self, "Path missing", "Path no longer exists.")

    # ----------------------
    # File operations
    # ----------------------
    def select_file_for_link(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select file to hard link & backup")
        if file_path:
            self.manual_file_link_and_backup(Path(file_path))

    def manual_file_link_and_backup(self, file_path: Path):
        try:
            # Hard link into BACKUP_DIR with same name (will not occupy extra space)
            link_target = BACKUP_DIR / file_path.name
            if not link_target.exists():
                os.link(file_path, link_target)
                self.log(f"Hard link created: {link_target}")
            else:
                self.log(f"Hard link already exists: {link_target}")

            # Timestamped backup copy (unencrypted copy)
            ts = now_str()
            backup_path = BACKUP_DIR / f"{file_path.name}_{ts}.bak"
            shutil.copy2(file_path, backup_path)
            self.log(f"Backup created: {backup_path}")

            # Optional SHA-256
            if self.hash_checkbox.isChecked():
                h = sha256_of(file_path)
                self.log(f"SHA-256({file_path.name}) = {h}")

        except Exception as e:
            self.log(f"File link/backup error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to hard link/backup: {e}")

    # ----------------------
    # Folder clone (non-versioned)
    # ----------------------
    def select_folder_for_clone(self):
        folder = QFileDialog.getExistingDirectory(self, "Select source folder to clone")
        if not folder:
            return
        dest = QFileDialog.getExistingDirectory(self, "Select destination parent folder")
        if not dest:
            return
        source = Path(folder)
        destination = Path(dest)
        # populate tree preview
        self.populate_tree(source)
        # start thread
        thread = FolderCloneThread(source, destination, preserve_name=True)
        self._start_clone_thread(thread)

    # ----------------------
    # Folder clone (versioned)
    # ----------------------
    def select_folder_for_version_clone(self):
        folder = QFileDialog.getExistingDirectory(self, "Select source folder to clone (versioned)")
        if not folder:
            return
        dest = QFileDialog.getExistingDirectory(self, "Select destination parent folder")
        if not dest:
            return
        source = Path(folder)
        destination = Path(dest)
        self.populate_tree(source)
        thread = FolderCloneVersionThread(source, destination)
        self._start_clone_thread(thread)

    def _start_clone_thread(self, thread: QThread):
        # Connect signals generically for both clone types
        if isinstance(thread, FolderCloneThread) or isinstance(thread, FolderCloneVersionThread):
            thread.progress.connect(self.progress.setValue)
            thread.log_signal.connect(self.log)
            thread.finished_signal.connect(self.on_clone_finished)
            self.current_clone_thread = thread
            thread.start()
            self.log("Started clone operation...")

    def on_clone_finished(self, path: Path):
        if path.exists():
            self.log(f"Clone finished: {path}")
            # Offer to open or populate tree
            if QMessageBox.question(self, "Clone finished", f"Clone completed: {path}\nPopulate tree view with this folder?") == QMessageBox.Yes:
                self.populate_tree(path)
        else:
            self.log("Clone finished with no path (error).")

    # ----------------------
    # Restore version
    # ----------------------
    def restore_version_dialog(self):
        dest_parent = QFileDialog.getExistingDirectory(self, "Select destination parent folder that contains versions (choose folder with Source_v1 etc.)")
        if not dest_parent:
            return
        dest_parent = Path(dest_parent)
        # List version folders
        versions = [p for p in dest_parent.iterdir() if p.is_dir()]
        if not versions:
            QMessageBox.information(self, "No versions", "No version folders found in chosen parent.")
            return
        names = [p.name for p in versions]
        choice, ok = QInputDialog.getItem(self, "Choose version to restore", "Versions:", names, 0, False)
        if not ok:
            return
        chosen = dest_parent / choice
        # Choose restore target
        restore_target = QFileDialog.getExistingDirectory(self, "Select folder to restore into (destination parent)")
        if not restore_target:
            return
        restore_target = Path(restore_target)
        # Copy structure by creating hard links (if original files still exist) or copying otherwise
        confirm = QMessageBox.question(self, "Confirm restore",
                                       f"Restore {chosen} into {restore_target}?\nFiles will be hard-linked where possible.")
        if confirm != QMessageBox.Yes:
            return
        self._restore_version(chosen, restore_target)

    def _restore_version(self, version_folder: Path, restore_parent: Path):
        # We'll create restore_parent / version_folder.name_restored (to avoid collisions)
        target_root = restore_parent / f"{version_folder.name}_restored_{now_str('%Y%m%d%H%M%S')}"
        target_root.mkdir(parents=True, exist_ok=True)
        self.log(f"Restoring {version_folder} → {target_root}")
        # Walk files and try to hard link to original source if possible; otherwise copy
        files = [p for p in version_folder.rglob("*") if p.is_file()]
        total = len(files) or 1
        count = 0
        for f in files:
            rel = f.relative_to(version_folder)
            tgt = target_root / rel
            tgt.parent.mkdir(parents=True, exist_ok=True)
            # Ideally f is already a hard link to original; linking f to tgt will create another hard link pointing to same inode (good)
            try:
                os.link(f, tgt)
                self.log(f"Restored by hard link: {tgt}")
            except Exception as e:
                # fallback to copy
                try:
                    shutil.copy2(f, tgt)
                    self.log(f"Restored by copy: {tgt}")
                except Exception as e2:
                    self.log(f"Restore error {f} -> {tgt}: {e2}")
            count += 1
            self.progress.setValue(int(count / total * 100))
        self.progress.setValue(100)
        self.log(f"Restore completed: {target_root}")
        if QMessageBox.question(self, "Restore finished", f"Restore finished: {target_root}\nPopulate tree view?") == QMessageBox.Yes:
            self.populate_tree(target_root)

    # ----------------------
    # Encryption / Decryption
    # ----------------------
    def select_files_for_encrypt(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select files to encrypt")
        if not files:
            return
        paths = [Path(f) for f in files]
        self.start_encrypt_files(paths)

    def start_encrypt_files(self, files: List[Path]):
        thread = FileEncryptThread(files, self.key)
        thread.progress.connect(self.progress.setValue)
        thread.log_signal.connect(self.log)
        thread.finished_signal.connect(lambda res: self.log(f"Encrypted {len(res)} files."))
        self.current_encrypt_thread = thread
        thread.start()
        self.log(f"Encryption started for {len(files)} files.")

    def select_file_for_decrypt(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select .enc file to decrypt")
        if not file:
            return
        try:
            enc = Path(file)
            with open(enc, "rb") as rf:
                nonce = rf.read(16)
                tag = rf.read(16)
                ciphertext = rf.read()
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            out = enc.with_suffix(".dec")
            with open(out, "wb") as wf:
                wf.write(plaintext)
            self.log(f"Decrypted: {out}")
            QMessageBox.information(self, "Decrypted", f"Output: {out}")
        except Exception as e:
            self.log(f"Decryption error: {e}")
            QMessageBox.critical(self, "Error", f"Decryption failed: {e}")

    # ----------------------
    # Secure delete
    # ----------------------
    def select_file_for_secure_delete(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select file to securely delete")
        if not file:
            return
        p = Path(file)
        confirm = QMessageBox.question(self, "Confirm secure delete", f"Permanently wipe and delete:\n{p}")
        if confirm == QMessageBox.Yes:
            self.secure_delete(p)

    def secure_delete(self, file_path: Path, passes: int = 3):
        try:
            if not file_path.exists():
                self.log(f"Secure delete: file not found {file_path}")
                return
            size = file_path.stat().st_size
            # Overwrite with random data passes times
            with open(file_path, "r+b") as f:
                for i in range(passes):
                    f.seek(0)
                    # write in chunks for large files
                    remaining = size
                    chunk = 1024 * 1024
                    while remaining > 0:
                        to_write = min(chunk, remaining)
                        f.write(os.urandom(to_write))
                        remaining -= to_write
                    f.flush()
                    os.fsync(f.fileno())
                # truncate and remove
            file_path.unlink()
            self.log(f"Securely deleted {file_path} (passes={passes})")
        except Exception as e:
            self.log(f"Secure delete error: {e}")
            QMessageBox.critical(self, "Error", f"Secure delete failed: {e}")

    # ----------------------
    # Misc / UI helpers
    # ----------------------
    def toggle_mode(self):
        self.dark_mode = not self.dark_mode
        self.apply_style()
        self.mode_button.setText("Toggle Light Mode" if self.dark_mode else "Toggle Dark Mode")
        self.log("Toggled UI mode.")

    def apply_style(self):
        if self.dark_mode:
            self.setStyleSheet("""
                QWidget { background: #111214; color: #e6e6e6; }
                QPushButton { background: #2b2b2f; color: #e6e6e6; padding: 8px; border-radius: 6px; }
                QPushButton:hover { background: #3a3a3f; }
                QTreeWidget, QTextEdit { background: #0f1112; color: #e6e6e6; }
                QProgressBar { background: #2b2b2b; color: #e6e6e6; border-radius: 6px; }
            """)
        else:
            self.setStyleSheet("""
                QWidget { background: #f6f7f9; color: #111111; }
                QPushButton { background: #e8eef8; color: #111111; padding: 8px; border-radius: 6px; }
                QPushButton:hover { background: #d7e6fb; }
                QTreeWidget, QTextEdit { background: #ffffff; color: #111111; }
                QProgressBar { background: #e8e8e8; color: #111111; border-radius: 6px; }
            """)

# ----------------------
# Run the app
# ----------------------
def main():
    app = QApplication(sys.argv)
    win = AdvancedFileManager()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
