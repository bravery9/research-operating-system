from invariant_os.core.models import PatchChangeType
from invariant_os.patchdiff.parser import parse_unified_diff


def test_parse_unified_diff_records_changed_file_hunk_and_added_lines():
    diff_text = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -10,3 +10,4 @@ def handler():
 context
-old_call(user_path)
+new_call(user_path)
+audit_marker(user_path)
 done
"""

    files = parse_unified_diff(diff_text)

    assert len(files) == 1
    changed = files[0]
    assert changed.id == "patch_file_0001"
    assert changed.old_path == "app.py"
    assert changed.new_path == "app.py"
    assert changed.change_type == PatchChangeType.MODIFIED
    assert len(changed.hunks) == 1
    assert changed.hunks[0].id == "patch_hunk_0001_0001"
    assert changed.hunks[0].old_start == 10
    assert changed.hunks[0].old_count == 3
    assert changed.hunks[0].new_start == 10
    assert changed.hunks[0].new_count == 4
    assert changed.hunks[0].removed_lines == [11]
    assert changed.hunks[0].added_lines == [11, 12]
    assert changed.hunks[0].context == "def handler():"


def test_parse_unified_diff_detects_added_deleted_and_renamed_files():
    added = parse_unified_diff(
        """diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,1 @@
+print("safe")
"""
    )
    deleted = parse_unified_diff(
        """diff --git a/old.py b/old.py
deleted file mode 100644
--- a/old.py
+++ /dev/null
@@ -1,1 +0,0 @@
-print("safe")
"""
    )
    renamed = parse_unified_diff(
        """diff --git a/old.py b/new.py
similarity index 88%
rename from old.py
rename to new.py
--- a/old.py
+++ b/new.py
@@ -1,1 +1,1 @@
-value = 1
+value = 2
"""
    )

    assert added[0].change_type == PatchChangeType.ADDED
    assert added[0].old_path is None
    assert added[0].new_path == "new.py"

    assert deleted[0].change_type == PatchChangeType.DELETED
    assert deleted[0].old_path == "old.py"
    assert deleted[0].new_path is None

    assert renamed[0].change_type == PatchChangeType.RENAMED
    assert renamed[0].old_path == "old.py"
    assert renamed[0].new_path == "new.py"


def test_parse_unified_diff_rejects_non_local_paths():
    diff_text = """diff --git a/../secret.py b/../secret.py
--- a/../secret.py
+++ b/../secret.py
@@ -1,1 +1,1 @@
-a
+b
"""

    try:
        parse_unified_diff(diff_text)
    except ValueError as error:
        assert "non-local file paths" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_parse_unified_diff_returns_empty_list_for_empty_diff():
    assert parse_unified_diff("") == []
