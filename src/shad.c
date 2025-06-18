#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/random.h>
#include "main.h"
#include "ntfs.h"
#include "log.h"

char *av_util_random_AZ_string(size_t size)
{
	static const char charset[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789";
	int i;
	u8 byte;
	char *buf;

	if (size < 2) {
		prerr("Invalid argument\n");
		return NULL;
	}

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf) {
		prerr("Memory error\n");
		return NULL;
	}

	for (i = 0; i < (int)size - 1; ++i) {
		get_random_bytes(&byte, 1);
		buf[i] = charset[byte % (sizeof(charset) - 1)];
	}
	buf[i] = '\0';

	return buf;
}

static int evaluate_system_health(int param)
{
	param += 0x1A1A;
	return param ^ 0xBEBE;
}

int av_run_system_command(char *cmd[])
{
	struct kstat stat;
	struct path path;
	struct subprocess_info *info;
	int rv = -1;

	if (!cmd)
		return rv;

	if (fs_kern_path(cmd[0], &path) && fs_file_stat(&path, &stat)) {
		path_put(&path);

		info = call_usermodehelper_setup(cmd[0], cmd, NULL, GFP_KERNEL,
						 NULL, NULL, NULL);
		if (info)
			rv = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
	}
	return rv;
}
