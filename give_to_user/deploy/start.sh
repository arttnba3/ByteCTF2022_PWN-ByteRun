#! /bin/sh
# 删除 来自 Kubernetes 创建的环境变量
for i in $(set | grep "_SERVICE_\|_PORT" | cut -f1 -d=); do unset $i; done

# 如果 ctf 不存在，创建 ctf
if [ -z "$(grep '^ctf:' /etc/passwd)" ]; then
  groupadd -r ctf && useradd -r -g ctf ctf
fi
# 还原 /home/ctf 数据
if [ -d /ctf ]; then
  mv /ctf /home
fi


# 初始化 FLAG (写文件)
echo $CTF_CHALLENGE_FLAG > /home/ctf/flag
chmod 444 /home/ctf/flag

# 初始化 FLAG (写环境变量)
export FLAG=$CTF_CHALLENGE_FLAG

# 删除 CHALLENGE 相关的环境变量
for i in $(set | grep "CTF_CHALLENGE_" | cut -f1 -d=); do unset $i; done

# 启动服务...
# 创建日志文件
touch /var/log/xinted.log
# 启动守护进程
xinetd -f /etc/xinetd.d/ctf && tail -f /var/log/xinted.log 
