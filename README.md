# Dexscan
### FEATURES
- Very fast (Full scan: <10 mins, Quick scan: <5 mins)
- TCP and UDP ports together
- Gives a list of open ports, pre-recon, in less than 10 seconds _(maybe inaccurate)_
- Gives suggestions post-recon to begin working with instantly
- Scan results saved in a folder named **0machines** located in `$HOME` 
- Full Scan is 99.99% accurate, covering ALL TCP ports and 100 common UDP ports.

### USAGE
```bash
git clone
cd dexscan && chmod +x dexscan.sh

./dexscan.sh <IP>                   #--QUICK SCAN
./dexscan.sh <IP> <folder_name>     #--FULL SCAN
```

### SAMPLES
