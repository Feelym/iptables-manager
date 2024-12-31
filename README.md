## iptables-manager
在IPv4转发的基础上增加对于IPv6转发的支持<br>
并且修改为用户自主选择转发协议是tcp还是udp<br>
原版本来源：https://www.nodeseek.com/post-196550-1<br>
自用版本iptables双栈转发<br>
在debian11上测试通过，但无法实现双栈互转，只能v4 to v4、v6 to v6<br>
## 使用方法：

```
curl -sS -O https://raw.githubusercontent.com/Feelym/iptables-manager/main/iptables-manager.sh && chmod +x iptables-manager.sh && ./iptables-manager.sh
```


### 当脚本运行时候出现下面错误：

```
sysctl: cannot stat /proc/sys/net/netfilter/nf_conntrack_max: No such file or directory
sysctl: cannot stat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established: No such file or directory
sysctl: cannot stat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait: No such file or directory
sysctl: cannot stat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait: No such file or directory
sysctl: cannot stat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_fin_wait: No such file or directory
```

### 解决方法：

```
sudo modprobe nf_conntrack
```
