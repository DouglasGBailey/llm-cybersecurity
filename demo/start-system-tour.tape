# Records a full walkthrough of every top-level path through
# start-system.sh's interactive menu: scan, view report, dashboard,
# REST API, tests, and lab-target management (start/stop DVWA,
# deploy/decline-delete Kubernetes Goat), then exit.
#
# Run from the project root:
#   VHS_NO_SANDBOX=true vhs demo/start-system-tour.tape

Output demo/start-system-all-paths.mp4

Set Shell bash
Set FontSize 16
Set Width 1600
Set Height 900
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

Hide
Type "clear"
Enter
Sleep 500ms
Show

# Launch the menu
Type "./start-system.sh"
Enter
Sleep 1.5s

# --- 1) Run a scan ---
Type "1"
Enter
Sleep 500ms
Type "1"
Enter
Sleep 500ms
Type "recon,webapp"
Enter
Sleep 500ms
Type "n"
Enter
Sleep 300ms
Type "n"
Enter
Sleep 2s

# --- 2) View a report ---
Type "2"
Enter
Sleep 800ms
Type "1"
Enter
Sleep 1.5s
Type "q"
Sleep 800ms

# --- 3) Regenerate dashboard ---
Type "3"
Enter
Sleep 1.5s

# --- 4) Start REST API server, then stop it ---
Type "4"
Enter
Sleep 2s
Ctrl+C
Sleep 1.5s

# --- 5) Run test suite ---
Type "5"
Enter
Sleep 4s

# --- 6) Lab target management ---
Type "6"
Enter
Sleep 1s

# Start/repair DVWA (already up -- shows the auto-repair check)
Type "1"
Enter
Sleep 3s

# Stop DVWA (confirmed) ...
Type "2"
Enter
Sleep 500ms
Type "y"
Enter
Sleep 2s

# ... then start it again to restore state
Type "1"
Enter
Sleep 3s

# Create/deploy Kubernetes Goat (already deployed -- idempotent)
Type "3"
Enter
Sleep 2s

# Delete Kubernetes Goat cluster -- decline, proving the safety
# confirmation actually blocks a destructive action
Type "4"
Enter
Sleep 500ms
Type "n"
Enter
Sleep 1s

# Back to the main menu
Type "5"
Enter
Sleep 800ms

# --- 7) Exit ---
Type "7"
Enter
Sleep 1s
