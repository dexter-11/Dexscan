# Dexscan
Made for HTB / OffSec PG / THM / PWK and OSCP!
_ _ _
### FEATURES
- 2 modes: Quick and Full Scans
- Very fast (Full scan: <10 mins, Quick scan: <5 mins)
- TCP and UDP ports together
- Gives a list of open ports, pre-recon, in less than 10 seconds _(maybe inaccurate)_
- Gives suggestions post-recon to begin working with instantly
- Scan results saved in a folder named **0machines** located in `$HOME` 
- Full Scan is 99.99% accurate, covering ALL TCP ports and 100 common UDP ports.

### USAGE
```bash
git clone https://github.com/dexter-11/Dexscan
cd dexscan && chmod +x dexscan.sh

./dexscan.sh <IP>                   #--QUICK SCAN
./dexscan.sh <IP> <folder_name>     #--FULL SCAN
```

### SAMPLES
- Quick Scan <br>
![image](https://user-images.githubusercontent.com/55249292/167408826-2b01fe5c-3f1e-4ae4-b0e3-c08b8f0fccbb.png)
- Full Scan <br>
![image](https://user-images.githubusercontent.com/55249292/167408217-224731b0-7f58-4015-9b3b-b162b2538bab.png)
![image](https://user-images.githubusercontent.com/55249292/167408247-a1ef2a2f-a0a6-4332-8a73-aef36d32e806.png)


### ToDo
- [ ] Option to add hostname to `/etc/host` automatically
