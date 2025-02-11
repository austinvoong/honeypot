## Network Scanner
The scanner will now work in both modes, though with reduced capabilities when running without root privileges. 

Root privileges:
```bash
python examples/scan_network.py
```

No root privileges:
```bash
sudo python examples/scan_network.py
```
# With root privileges, you'll get:

- SYN stealth scanning
- UDP scanning
- OS detection


# Without root privileges, you'll get:

- Basic TCP connect scanning
- Service version detection
- No OS detection