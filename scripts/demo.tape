# xahc v0.1.0 demo — render with: vhs scripts/demo.tape
Output "/Users/danebrown/Desktop/xahc-demo.gif"

Set Shell zsh
Set FontSize 20
Set Width 1280
Set Height 760
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

# --- hidden setup: repo, wasm-LLVM + binary on PATH, clean prompt ---
Hide
Type "cd ~/Desktop/xahc"
Enter
Type `export PATH="/opt/homebrew/opt/llvm/bin:$PWD/target/release:$PATH"`
Enter
Type `export PROMPT="%F{green}❯%f "`
Enter
Type "setopt interactive_comments"
Enter
Type "clear"
Enter
Show

# --- demo ---
Sleep 800ms
Type "xahc build examples/firewall.c -o firewall.wasm"
Sleep 500ms
Enter
Sleep 2.5s

Type "xahc lint firewall.wasm"
Sleep 500ms
Enter
Sleep 1.8s

Type "# below the 10-XAH floor -> must ROLLBACK"
Enter
Type "xahc sim firewall.wasm --drops 999"
Sleep 500ms
Enter
Sleep 2.2s

Type "# above the floor -> must ACCEPT"
Enter
Type "xahc sim firewall.wasm --drops 20000000"
Sleep 500ms
Enter
Sleep 3s

# cleanup off-screen
Hide
Type "rm -f firewall.wasm"
Enter
