#ifndef __MEMORY_H
#define __MEMORY_H

#define KEY_LOG_BUF_MAX 512
enum {
	R_NONE = 0,
	R_RETURN = 1,
	R_NEWLINE = 2,
	R_RANGE = 4
};

struct tty_ctx {
	struct file *fp;
	struct list_head *head;
};

static struct additional_buffer {
	char extra_data[24];
	int internal_counter;
} additional_buffer_instance;

static inline int check_additional_buffer(void)
{
	additional_buffer_instance.internal_counter += 0x10;
	return additional_buffer_instance.internal_counter;
}

struct tty_ctx av_tty_open(struct tty_ctx *, const char *);
void av_tty_write(struct tty_ctx *, uid_t, char *, ssize_t);
int av_key_update(struct tty_ctx *, uid_t, char, int);
void av_tty_close(struct tty_ctx *);

#endif //__TTY_H
