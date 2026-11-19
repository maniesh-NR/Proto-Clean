import subprocess
from pathlib import Path

MEMORY_FILE = Path(__file__).resolve().parent / "PROJECT_MEMORY.md"
NUM_COMMITS = 3  # Number of recent commits to pull diffs for

def get_recent_git_diffs():
    """Fetches recent commit metadata and diff patches using git log."""
    try:
        # Run git log with patch output for the last N commits
        result = subprocess.run(
            [
                "git", "log", 
                f"-n{NUM_COMMITS}", 
                "--pretty=format:### Commit: %h - %s (%an, %ad)", 
                "--date=short", 
                "--stat"
            ],
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8"
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running git command: {e}")
        return ""
    except FileNotFoundError:
        print("[!] Git is not installed or not found in system PATH.")
        return ""

def update_project_memory():
    diffs = get_recent_git_diffs()
    if not diffs:
        print("[!] No git history or changes found to update.")
        return

    section_header = "## Recent Progress & Git Activity"
    new_section = f"{section_header}\n\n```diff\n{diffs}\n```\n\n"

    # Read existing memory file if it exists
    if MEMORY_FILE.exists():
        content = MEMORY_FILE.read_text(encoding="utf-8")
        
        # If the recent activity section already exists, replace it
        if section_header in content:
            parts = content.split(section_header)
            # Find the end of this section (assume next '##' header or end of file)
            remainder = parts[1]
            next_header_idx = remainder.find("\n## ")
            if next_header_idx != -1:
                remaining_content = remainder[next_header_idx:]
            else:
                remaining_content = ""
            
            updated_content = parts[0].rstrip() + "\n\n" + new_section + remaining_content.lstrip()
        else:
            # Prepend right below the main title
            updated_content = content + "\n\n" + new_section
    else:
        # Initialize a new memory file if none exists
        updated_content = f"# Project Memory & State\n\n{new_section}"

    MEMORY_FILE.write_text(updated_content, encoding="utf-8")
    print(f"[✓] Successfully updated {MEMORY_FILE} with the last {NUM_COMMITS} commit summaries (stat).")

if __name__ == "__main__":
    update_project_memory()