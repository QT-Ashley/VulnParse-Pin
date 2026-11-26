# Charm VHS capture script for VulnParse-Pin v2.0.0 offline demo
# Run from repo root: vhs documentation/demo/vpp-demo.tape
# Produces: documentation/img/vpp-demo.gif (~15-20s playback)

Output documentation/img/vpp-demo.gif

Require vpp

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 700
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

# 1. Launch 100% offline demo pack (<2s) into interactive TUI
Type "vpp demo"
Enter
Sleep 2.5s

# 2. Filter to P1 / Act findings and inspect live score_trace
Type "1"
Sleep 1.5s
Down
Sleep 1.5s

# 3. Clear priority filter, cycle scoring track to exposure_weakness, then inspect Shadow Assets
Type "0"
Sleep 0.8s
Type "t"
Sleep 0.4s
Type "t"
Sleep 1.5s
Type "t"
Sleep 0.6s
Type "u"
Sleep 1.8s
Type "u"
Sleep 0.8s

# 4. Filter back to P1 and press 'e' to export Decision Defense Dossier (prints output path)
Type "1"
Sleep 0.8s
Type "e"
Sleep 2.2s

# 5. Quit TUI and confirm generated dossier files on disk
Type "q"
Sleep 0.8s
Type "ls -1 vpp_demo_output/*dossier*"
Enter
Sleep 2s
