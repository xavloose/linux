#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/ipc.h>
#include <linux/xacl.h>
#include <linux/xsecurity.h>
#include <linux/xinternal.h>

int
x_handle_shmat(const pid_t shm_cprid, const pid_t shm_lapid,
		const u64 shm_createtime, const kuid_t cuid, const int shmid)
{
	struct task_struct *task;

	if (!x_acl_is_enabled())
		return 1;

	rcu_read_lock();
	read_lock(&tasklist_lock);

	task = find_task_by_vpid(shm_cprid);

	if (unlikely(!task))
		task = find_task_by_vpid(shm_lapid);

	if (unlikely(task && (time_before_eq64(task->start_time, shm_createtime) ||
			      (task_pid_nr(task) == shm_lapid)) &&
		     (task->acl->mode & X_PROTSHM) &&
		     (task->acl != current->acl))) {
		read_unlock(&tasklist_lock);
		rcu_read_unlock();
		x_log_int3(X_DONT_AUDIT, X_SHMAT_ACL_MSG, X_GLOBAL_UID(cuid), shm_cprid, shmid);
		return 0;
	}
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	return 1;
}
