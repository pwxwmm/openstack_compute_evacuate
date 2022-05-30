### auto_check_compute_down
#### author: mmwei3
#### date: 2021/12/12

#### Instructions
```angular2html
This is openstack compute node ha!
func: 
1. auto check compute nodes health state, down or up, 

2. if check first down and Compute Status is disable:
   The compute node management network detected for fping tools.
       Start check vms for the down state compute node:
           if compute nodes management network and vms is Unreachable:
              Start an evacuation task for all active status vms on the compute node.
              And auto Send SMS and email notifications to all affected users about vms downtime
           else :
               Do nothing

```
#### Install

```shell
1. Configuration cmpha.conf
vim /etc/cmpha.conf

[ser]
OS_TENANT_NAME=admin
OS_PROJECT_NAME=admin
OS_USERNAME=admin
OS_PASSWORD=
OS_AUTH_URL=http://x.x.x.x:35357/v3
OS_DEFAULT_DOMAIN=Default
INTERVAL=20  # Interval of each probe


2. Run Docker
docker run -d --tty=true \
--net=host --restart=always \
-v /etc/localtime:/etc/localtime:ro \
--name=auto_evacuate \
-v /etc/cmpha.conf:/etc/cmpha.conf  \
pwxwmm/openstack_compute_evacuate:v1.0.0


3. Or another way to do it

Use linux systemctl managerment cmpha service
configuration cmpha.service

Usage: /etc/init.d/$DAEMON_NAME {start|stop|restart|status}
# systemctl start cmpha.service
# systemctl stop cmpha.service
# ststemctl restart cmpha.service


```

