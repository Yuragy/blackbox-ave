#ifndef __OWN_H
#define __OWN_H

#define AVE_VERSION "3.0.0"

struct own_backup_info {
	int backup_state;
	char note[32];
};

static inline void enhance_own_backup_info(struct own_backup_info *info)
{
	if (info) {
		info->backup_state ^= 0xDE77;
	}
}

#endif // __OWN_H
