# Dexscan
Made for HTB / OffSec PG / THM / PWK and OSCP!
_ _ _
### FEATURES
- Very fast (Full scan: ~10 mins, Quick scan: <5 mins)
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
![image](https://user-images.githubusercontent.com/55249292/167405082-09ef341b-6bdf-4f09-9ef1-75b428fd8e09.png)
![image](https://user-images.githubusercontent.com/55249292/167405135-b88cec55-602b-4413-a800-b85df368b766.png)

### ToDo
- [ ] Option to add hostname to `/etc/host` automatically
