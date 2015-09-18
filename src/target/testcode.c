int dump_mmsghdr(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_mq_attr(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_shmid_ds(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_ipc_perm(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_sembuf(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_msgbuf(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_long_long_unsigned_int(unsigned int value, char **param_str);
int dump_io_event(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_iocb(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_epoll_event(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_ustat(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_statfs64(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_statfs(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump___kernel_fsid_t(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_utimbuf(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_pollfd(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_sel_arg_struct(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_linux_dirent64(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_linux_dirent(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_old_linux_dirent(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_stat64(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_stat(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_mmap_arg_struct(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_unsigned_char_from_mem(unsigned int addr, char **param_str, struct target *target);
int dump_perf_event_attr(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_kexec_segment(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_short_unsigned_int(unsigned int value, char **param_str);
int dump_robust_list_head(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_robust_list(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_itimerspec(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_sigevent(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_getcpu_cache(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_rlimit64(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_rlimit(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_new_utsname(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_tms(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_sigaction(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_sigset_t(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_sysinfo(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump___user_cap_data_struct(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump___user_cap_header_struct(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump___sysctl_args(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_timex(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_timezone(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_itimerval(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_rusage(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_timeval(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_siginfo(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_sched_param(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_msghdr(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_iovec(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_sockaddr(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_char_from_mem(unsigned int addr, char **param_str, struct target *target);
int dump_long_int(unsigned int value, char **param_str);
int dump_timespec(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_long_int_from_mem(unsigned int addr, char **param_str, struct target *target);
int dump_oabi_sembuf(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_short_int_from_mem(unsigned int addr, char **param_str, struct target *target);
int dump_short_unsigned_int_from_mem(unsigned int addr, char **param_str, struct target *target);
int dump_oabi_epoll_event(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_unsigned_int(unsigned int value, char **param_str);
int dump_oldabi_stat64(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_long_long_int_from_mem(unsigned int addr, char **param_str, struct target *target);
int dump_unsigned_int_from_mem(unsigned int addr, char **param_str, struct target *target);
int dump_long_long_unsigned_int_from_mem(unsigned int addr, char **param_str, struct target *target);
int dump_long_long_int(unsigned int value, char **param_str);
int dump_int_from_mem(unsigned int addr, char **param_str, struct target *target);
int dump_pt_regs(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_old_sigaction(int depth, unsigned int addr, char **dumped_params, struct target *target);
int dump_long_unsigned_int_from_mem(unsigned int addr, char **param_str, struct target *target);
int dump_ptr(unsigned int value, char **param_str);
int dump_long_unsigned_int(unsigned int value, char **param_str);
int dump_int(unsigned int value, char **param_str);
int dump_n_bytes_from_mem(unsigned int addr, char **param_str, struct target *target, unsigned int size);
unsigned int read_ptr_from_mem(unsigned int addr, struct target *target);
int dump_str_from_mem(unsigned int addr, char **param_str, struct target *target);
char *copy_params(char **dumped_params, int nr_params, int *len);
void free_dumped_params(char **dumped_params, int nr_params);
int dump_generic(char **param_str, unsigned int size, char *format, unsigned int value);
char *dump_sys_setsid(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_sigsuspend(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_restart = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_oldmask = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_mask = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_restart, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_oldmask, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_mask, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_sigaction(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_sig = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_act = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_oact = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_sig, &dumped_params[0]);
    len += dump_ptr(arm_tracing_act, &dumped_params[1]);
    len += dump_ptr(arm_tracing_oact, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_sig, &dumped_params[0]);
    len += dump_old_sigaction(depth-1, arm_tracing_act, &dumped_params[1], target);
    len += dump_old_sigaction(depth-1, arm_tracing_oact, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_sigreturn(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_regs = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_regs, &param_str);
    return param_str;
  }

  dump_pt_regs(depth-1, arm_tracing_regs, &param_str, target);
  return param_str;
}

char *dump_sys_rt_sigreturn(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_regs = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_regs, &param_str);
    return param_str;
  }

  dump_pt_regs(depth-1, arm_tracing_regs, &param_str, target);
  return param_str;
}

char *dump_sys_fork(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_regs = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_regs, &param_str);
    return param_str;
  }

  dump_pt_regs(depth-1, arm_tracing_regs, &param_str, target);
  return param_str;
}

char *dump_sys_clone(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_clone_flags = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_newsp = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_parent_tidptr = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_tls_val = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_child_tidptr = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_regs = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_clone_flags, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_newsp, &dumped_params[1]);
    len += dump_ptr(arm_tracing_parent_tidptr, &dumped_params[2]);
    len += dump_int(arm_tracing_tls_val, &dumped_params[3]);
    len += dump_ptr(arm_tracing_child_tidptr, &dumped_params[4]);
    len += dump_ptr(arm_tracing_regs, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_clone_flags, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_newsp, &dumped_params[1]);
    len += dump_int_from_mem(arm_tracing_parent_tidptr, &dumped_params[2], target);
    len += dump_int(arm_tracing_tls_val, &dumped_params[3]);
    len += dump_int_from_mem(arm_tracing_child_tidptr, &dumped_params[4], target);
    len += dump_pt_regs(depth-1, arm_tracing_regs, &dumped_params[5], target);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_vfork(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_regs = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_regs, &param_str);
    return param_str;
  }

  dump_pt_regs(depth-1, arm_tracing_regs, &param_str, target);
  return param_str;
}

char *dump_sys_execve(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filenamei = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_argv = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_envp = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_regs = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filenamei, &dumped_params[0]);
    len += dump_ptr(arm_tracing_argv, &dumped_params[1]);
    len += dump_ptr(arm_tracing_envp, &dumped_params[2]);
    len += dump_ptr(arm_tracing_regs, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  arm_tracing_argv = read_ptr_from_mem(arm_tracing_argv, target);
  arm_tracing_envp = read_ptr_from_mem(arm_tracing_envp, target);
  if (depth == 1)
  {
    len += dump_str_from_mem(arm_tracing_filenamei, &dumped_params[0], target);
    len += dump_ptr(arm_tracing_argv, &dumped_params[1]);
    len += dump_ptr(arm_tracing_envp, &dumped_params[2]);
    len += dump_pt_regs(depth-1, arm_tracing_regs, &dumped_params[3], target);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 2)
  {
    len += dump_str_from_mem(arm_tracing_filenamei, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_argv, &dumped_params[1], target);
    len += dump_str_from_mem(arm_tracing_envp, &dumped_params[2], target);
    len += dump_pt_regs(depth-1, arm_tracing_regs, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_arm_fadvise64_64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_advice = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_offset = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_advice, &dumped_params[1]);
    len += dump_long_long_int(arm_tracing_offset, &dumped_params[2]);
    len += dump_long_long_int(arm_tracing_len, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_oabi_stat64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_oldabi_stat64(depth-1, arm_tracing_statbuf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_oabi_lstat64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_oldabi_stat64(depth-1, arm_tracing_statbuf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_oabi_fstat64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_oldabi_stat64(depth-1, arm_tracing_statbuf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_oabi_fstatat64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flag = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_filename, &dumped_params[1]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[2]);
    len += dump_int(arm_tracing_flag, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[1], target);
    len += dump_oldabi_stat64(depth-1, arm_tracing_statbuf, &dumped_params[2], target);
    len += dump_int(arm_tracing_flag, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_oabi_fcntl64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_cmd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_arg = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_cmd, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_arg, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_oabi_epoll_ctl(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_epfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_op = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_event = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_epfd, &dumped_params[0]);
    len += dump_int(arm_tracing_op, &dumped_params[1]);
    len += dump_int(arm_tracing_fd, &dumped_params[2]);
    len += dump_ptr(arm_tracing_event, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_epfd, &dumped_params[0]);
    len += dump_int(arm_tracing_op, &dumped_params[1]);
    len += dump_int(arm_tracing_fd, &dumped_params[2]);
    len += dump_oabi_epoll_event(depth-1, arm_tracing_event, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_oabi_epoll_wait(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_epfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_events = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_maxevents = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_timeout = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_epfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_events, &dumped_params[1]);
    len += dump_int(arm_tracing_maxevents, &dumped_params[2]);
    len += dump_int(arm_tracing_timeout, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_epfd, &dumped_params[0]);
    len += dump_oabi_epoll_event(depth-1, arm_tracing_events, &dumped_params[1], target);
    len += dump_int(arm_tracing_maxevents, &dumped_params[2]);
    len += dump_int(arm_tracing_timeout, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_oabi_semtimedop(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_semid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_tsops = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_nsops = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_timeout = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_semid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_tsops, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_nsops, &dumped_params[2]);
    len += dump_ptr(arm_tracing_timeout, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_semid, &dumped_params[0]);
    len += dump_oabi_sembuf(depth-1, arm_tracing_tsops, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_nsops, &dumped_params[2]);
    len += dump_timespec(depth-1, arm_tracing_timeout, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_oabi_semop(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_semid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_tsops = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_nsops = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_semid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_tsops, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_nsops, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_semid, &dumped_params[0]);
    len += dump_oabi_sembuf(depth-1, arm_tracing_tsops, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_nsops, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_oabi_ipc(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_call = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_first = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_second = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_third = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_ptr = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_fifth = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_call, &dumped_params[0]);
    len += dump_int(arm_tracing_first, &dumped_params[1]);
    len += dump_int(arm_tracing_second, &dumped_params[2]);
    len += dump_int(arm_tracing_third, &dumped_params[3]);
    len += dump_ptr(arm_tracing_ptr, &dumped_params[4]);
    len += dump_long_int(arm_tracing_fifth, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_call, &dumped_params[0]);
    len += dump_int(arm_tracing_first, &dumped_params[1]);
    len += dump_int(arm_tracing_second, &dumped_params[2]);
    len += dump_int(arm_tracing_third, &dumped_params[3]);
    len += dump_n_bytes_from_mem(arm_tracing_ptr, &dumped_params[4], target, 256);
    len += dump_long_int(arm_tracing_fifth, &dumped_params[5]);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_oabi_bind(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_addr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_addrlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_addr, &dumped_params[1]);
    len += dump_int(arm_tracing_addrlen, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_sockaddr(depth-1, arm_tracing_addr, &dumped_params[1], target);
    len += dump_int(arm_tracing_addrlen, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_oabi_connect(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_addr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_addrlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_addr, &dumped_params[1]);
    len += dump_int(arm_tracing_addrlen, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_sockaddr(depth-1, arm_tracing_addr, &dumped_params[1], target);
    len += dump_int(arm_tracing_addrlen, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_oabi_sendto(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buff = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_addr = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_addrlen = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buff, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_ptr(arm_tracing_addr, &dumped_params[4]);
    len += dump_int(arm_tracing_addrlen, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_n_bytes_from_mem(arm_tracing_buff, &dumped_params[1], target, 256);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_sockaddr(depth-1, arm_tracing_addr, &dumped_params[4], target);
    len += dump_int(arm_tracing_addrlen, &dumped_params[5]);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_oabi_sendmsg(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_msg = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_msg, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_msghdr(depth-1, arm_tracing_msg, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_oabi_socketcall(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_call = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_args = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_call, &dumped_params[0]);
    len += dump_ptr(arm_tracing_args, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_call, &dumped_params[0]);
    len += dump_long_unsigned_int_from_mem(arm_tracing_args, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_nice(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_increment = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_increment, &param_str);
  return param_str;
}

char *dump_sys_sched_setscheduler(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_policy = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_param = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_int(arm_tracing_policy, &dumped_params[1]);
    len += dump_ptr(arm_tracing_param, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_int(arm_tracing_policy, &dumped_params[1]);
    len += dump_sched_param(depth-1, arm_tracing_param, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_sched_setparam(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_param = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_param, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_sched_param(depth-1, arm_tracing_param, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_sched_getscheduler(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_pid, &param_str);
  return param_str;
}

char *dump_sys_sched_getparam(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_param = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_param, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_sched_param(depth-1, arm_tracing_param, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_sched_setaffinity(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_user_mask_ptr = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_ptr(arm_tracing_user_mask_ptr, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_long_unsigned_int_from_mem(arm_tracing_user_mask_ptr, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_sched_getaffinity(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_user_mask_ptr = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_ptr(arm_tracing_user_mask_ptr, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_long_unsigned_int_from_mem(arm_tracing_user_mask_ptr, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_sched_yield(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_sched_get_priority_max(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_policy = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_policy, &param_str);
  return param_str;
}

char *dump_sys_sched_get_priority_min(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_policy = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_policy, &param_str);
  return param_str;
}

char *dump_sys_sched_rr_get_interval(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_interval = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_interval, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_timespec(depth-1, arm_tracing_interval, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_set_tid_address(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_tidptr = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_tidptr, &param_str);
    return param_str;
  }

  dump_int_from_mem(arm_tracing_tidptr, &param_str, target);
  return param_str;
}

char *dump_sys_unshare(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_unshare_flags = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_long_unsigned_int(arm_tracing_unshare_flags, &param_str);
  return param_str;
}

char *dump_sys_personality(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_personality = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_personality, &param_str);
  return param_str;
}

char *dump_sys_syslog(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_type = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_type, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[1]);
    len += dump_int(arm_tracing_len, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_type, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_buf, &dumped_params[1], target);
    len += dump_int(arm_tracing_len, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_exit(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_error_code = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_error_code, &param_str);
  return param_str;
}

char *dump_sys_exit_group(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_error_code = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_error_code, &param_str);
  return param_str;
}

char *dump_sys_waitid(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_upid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_infop = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_options = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_ru = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_which, &dumped_params[0]);
    len += dump_int(arm_tracing_upid, &dumped_params[1]);
    len += dump_ptr(arm_tracing_infop, &dumped_params[2]);
    len += dump_int(arm_tracing_options, &dumped_params[3]);
    len += dump_ptr(arm_tracing_ru, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_which, &dumped_params[0]);
    len += dump_int(arm_tracing_upid, &dumped_params[1]);
    len += dump_siginfo(depth-1, arm_tracing_infop, &dumped_params[2], target);
    len += dump_int(arm_tracing_options, &dumped_params[3]);
    len += dump_rusage(depth-1, arm_tracing_ru, &dumped_params[4], target);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_wait4(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_upid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_stat_addr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_options = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_ru = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_upid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_stat_addr, &dumped_params[1]);
    len += dump_int(arm_tracing_options, &dumped_params[2]);
    len += dump_ptr(arm_tracing_ru, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_upid, &dumped_params[0]);
    len += dump_int_from_mem(arm_tracing_stat_addr, &dumped_params[1], target);
    len += dump_int(arm_tracing_options, &dumped_params[2]);
    len += dump_rusage(depth-1, arm_tracing_ru, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_getitimer(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_value = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_which, &dumped_params[0]);
    len += dump_ptr(arm_tracing_value, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_which, &dumped_params[0]);
    len += dump_itimerval(depth-1, arm_tracing_value, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setitimer(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_value = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_ovalue = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_which, &dumped_params[0]);
    len += dump_ptr(arm_tracing_value, &dumped_params[1]);
    len += dump_ptr(arm_tracing_ovalue, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_which, &dumped_params[0]);
    len += dump_itimerval(depth-1, arm_tracing_value, &dumped_params[1], target);
    len += dump_itimerval(depth-1, arm_tracing_ovalue, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_time(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_tloc = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_tloc, &param_str);
    return param_str;
  }

  dump_long_int_from_mem(arm_tracing_tloc, &param_str, target);
  return param_str;
}

char *dump_sys_stime(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_tptr = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_tptr, &param_str);
    return param_str;
  }

  dump_long_int_from_mem(arm_tracing_tptr, &param_str, target);
  return param_str;
}

char *dump_sys_gettimeofday(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_tv = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_tz = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_tv, &dumped_params[0]);
    len += dump_ptr(arm_tracing_tz, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_timeval(depth-1, arm_tracing_tv, &dumped_params[0], target);
    len += dump_timezone(depth-1, arm_tracing_tz, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_settimeofday(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_tv = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_tz = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_tv, &dumped_params[0]);
    len += dump_ptr(arm_tracing_tz, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_timeval(depth-1, arm_tracing_tv, &dumped_params[0], target);
    len += dump_timezone(depth-1, arm_tracing_tz, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_adjtimex(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_txc_p = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_txc_p, &param_str);
    return param_str;
  }

  dump_timex(depth-1, arm_tracing_txc_p, &param_str, target);
  return param_str;
}

char *dump_sys_sysctl(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_args = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_args, &param_str);
    return param_str;
  }

  dump___sysctl_args(depth-1, arm_tracing_args, &param_str, target);
  return param_str;
}

char *dump_sys_capget(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_header = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_dataptr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump___user_cap_header_struct(depth, arm_tracing_header, &dumped_params[0], target);
    len += dump___user_cap_data_struct(depth, arm_tracing_dataptr, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_capset(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_header = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_data = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump___user_cap_header_struct(depth, arm_tracing_header, &dumped_params[0], target);
    len += dump___user_cap_data_struct(depth, arm_tracing_data, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_ptrace(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_request = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_addr = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_data = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_int(arm_tracing_request, &dumped_params[0]);
    len += dump_long_int(arm_tracing_pid, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_addr, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_data, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_alarm(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_seconds = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_seconds, &param_str);
  return param_str;
}

char *dump_sys_getpid(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_getppid(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_getuid(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_geteuid(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_getgid(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_getegid(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_gettid(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_sysinfo(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_info = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_info, &param_str);
    return param_str;
  }

  dump_sysinfo(depth-1, arm_tracing_info, &param_str, target);
  return param_str;
}

char *dump_sys_restart_syscall(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_rt_sigprocmask(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_how = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_nset = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_oset = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_sigsetsize = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_how, &dumped_params[0]);
    len += dump_ptr(arm_tracing_nset, &dumped_params[1]);
    len += dump_ptr(arm_tracing_oset, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_how, &dumped_params[0]);
    len += dump_sigset_t(depth-1, arm_tracing_nset, &dumped_params[1], target);
    len += dump_sigset_t(depth-1, arm_tracing_oset, &dumped_params[2], target);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_rt_sigpending(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_set = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_sigsetsize = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_set, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_sigset_t(depth-1, arm_tracing_set, &dumped_params[0], target);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_rt_sigtimedwait(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_uthese = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_uinfo = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_uts = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_sigsetsize = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_uthese, &dumped_params[0]);
    len += dump_ptr(arm_tracing_uinfo, &dumped_params[1]);
    len += dump_ptr(arm_tracing_uts, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_sigset_t(depth-1, arm_tracing_uthese, &dumped_params[0], target);
    len += dump_siginfo(depth-1, arm_tracing_uinfo, &dumped_params[1], target);
    len += dump_timespec(depth-1, arm_tracing_uts, &dumped_params[2], target);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_kill(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_sig = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_int(arm_tracing_sig, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_tgkill(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_tgid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_sig = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_tgid, &dumped_params[0]);
    len += dump_int(arm_tracing_pid, &dumped_params[1]);
    len += dump_int(arm_tracing_sig, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_tkill(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_sig = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_int(arm_tracing_sig, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_rt_sigqueueinfo(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_sig = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_uinfo = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_int(arm_tracing_sig, &dumped_params[1]);
    len += dump_ptr(arm_tracing_uinfo, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_int(arm_tracing_sig, &dumped_params[1]);
    len += dump_siginfo(depth-1, arm_tracing_uinfo, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_rt_tgsigqueueinfo(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_tgid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_sig = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_uinfo = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_tgid, &dumped_params[0]);
    len += dump_int(arm_tracing_pid, &dumped_params[1]);
    len += dump_int(arm_tracing_sig, &dumped_params[2]);
    len += dump_ptr(arm_tracing_uinfo, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_tgid, &dumped_params[0]);
    len += dump_int(arm_tracing_pid, &dumped_params[1]);
    len += dump_int(arm_tracing_sig, &dumped_params[2]);
    len += dump_siginfo(depth-1, arm_tracing_uinfo, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_sigpending(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_set = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_set, &param_str);
    return param_str;
  }

  dump_long_unsigned_int_from_mem(arm_tracing_set, &param_str, target);
  return param_str;
}

char *dump_sys_sigprocmask(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_how = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_nset = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_oset = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_how, &dumped_params[0]);
    len += dump_ptr(arm_tracing_nset, &dumped_params[1]);
    len += dump_ptr(arm_tracing_oset, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_how, &dumped_params[0]);
    len += dump_long_unsigned_int_from_mem(arm_tracing_nset, &dumped_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_oset, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_rt_sigaction(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_sig = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_act = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_oact = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_sigsetsize = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_sig, &dumped_params[0]);
    len += dump_ptr(arm_tracing_act, &dumped_params[1]);
    len += dump_ptr(arm_tracing_oact, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_sig, &dumped_params[0]);
    len += dump_sigaction(depth-1, arm_tracing_act, &dumped_params[1], target);
    len += dump_sigaction(depth-1, arm_tracing_oact, &dumped_params[2], target);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_pause(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_rt_sigsuspend(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_unewset = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_sigsetsize = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_unewset, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_sigset_t(depth-1, arm_tracing_unewset, &dumped_params[0], target);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setpriority(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_who = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_niceval = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_which, &dumped_params[0]);
    len += dump_int(arm_tracing_who, &dumped_params[1]);
    len += dump_int(arm_tracing_niceval, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_getpriority(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_who = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_which, &dumped_params[0]);
    len += dump_int(arm_tracing_who, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_reboot(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_magic1 = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_magic2 = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_cmd = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_arg = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_magic1, &dumped_params[0]);
    len += dump_int(arm_tracing_magic2, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_cmd, &dumped_params[2]);
    len += dump_ptr(arm_tracing_arg, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_magic1, &dumped_params[0]);
    len += dump_int(arm_tracing_magic2, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_cmd, &dumped_params[2]);
    len += dump_n_bytes_from_mem(arm_tracing_arg, &dumped_params[3], target, 256);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_setregid(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_rgid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_egid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_rgid, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_egid, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setgid(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_gid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_gid, &param_str);
  return param_str;
}

char *dump_sys_setreuid(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ruid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_euid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_ruid, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_euid, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setuid(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_uid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_uid, &param_str);
  return param_str;
}

char *dump_sys_setresuid(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ruid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_euid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_suid = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_ruid, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_euid, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_suid, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_getresuid(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ruid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_euid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_suid = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_ruid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_euid, &dumped_params[1]);
    len += dump_ptr(arm_tracing_suid, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_ruid, &dumped_params[0], target);
    len += dump_unsigned_int_from_mem(arm_tracing_euid, &dumped_params[1], target);
    len += dump_unsigned_int_from_mem(arm_tracing_suid, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_setresgid(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_rgid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_egid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_sgid = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_rgid, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_egid, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_sgid, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_getresgid(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_rgid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_egid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_sgid = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_rgid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_egid, &dumped_params[1]);
    len += dump_ptr(arm_tracing_sgid, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_rgid, &dumped_params[0], target);
    len += dump_unsigned_int_from_mem(arm_tracing_egid, &dumped_params[1], target);
    len += dump_unsigned_int_from_mem(arm_tracing_sgid, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_setfsuid(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_uid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_uid, &param_str);
  return param_str;
}

char *dump_sys_setfsgid(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_gid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_gid, &param_str);
  return param_str;
}

char *dump_sys_times(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_tbuf = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_tbuf, &param_str);
    return param_str;
  }

  dump_tms(depth-1, arm_tracing_tbuf, &param_str, target);
  return param_str;
}

char *dump_sys_setpgid(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_pgid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_int(arm_tracing_pgid, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_getpgid(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_pid, &param_str);
  return param_str;
}

char *dump_sys_getpgrp(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_getsid(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_pid, &param_str);
  return param_str;
}

char *dump_sys_newuname(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_name, &param_str);
    return param_str;
  }

  dump_new_utsname(depth-1, arm_tracing_name, &param_str, target);
  return param_str;
}

char *dump_sys_sethostname(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_name, &dumped_params[0]);
    len += dump_int(arm_tracing_len, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[0], target);
    len += dump_int(arm_tracing_len, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_gethostname(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_name, &dumped_params[0]);
    len += dump_int(arm_tracing_len, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[0], target);
    len += dump_int(arm_tracing_len, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setdomainname(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_name, &dumped_params[0]);
    len += dump_int(arm_tracing_len, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[0], target);
    len += dump_int(arm_tracing_len, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_old_getrlimit(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_resource = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_rlim = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_resource, &dumped_params[0]);
    len += dump_ptr(arm_tracing_rlim, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_resource, &dumped_params[0]);
    len += dump_rlimit(depth-1, arm_tracing_rlim, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_getrlimit(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_resource = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_rlim = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_resource, &dumped_params[0]);
    len += dump_ptr(arm_tracing_rlim, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_resource, &dumped_params[0]);
    len += dump_rlimit(depth-1, arm_tracing_rlim, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_prlimit64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_resource = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_new_rlim = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_old_rlim = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_resource, &dumped_params[1]);
    len += dump_ptr(arm_tracing_new_rlim, &dumped_params[2]);
    len += dump_ptr(arm_tracing_old_rlim, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_resource, &dumped_params[1]);
    len += dump_rlimit64(depth-1, arm_tracing_new_rlim, &dumped_params[2], target);
    len += dump_rlimit64(depth-1, arm_tracing_old_rlim, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_setrlimit(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_resource = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_rlim = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_resource, &dumped_params[0]);
    len += dump_ptr(arm_tracing_rlim, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_resource, &dumped_params[0]);
    len += dump_rlimit(depth-1, arm_tracing_rlim, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_getrusage(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_who = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_ru = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_who, &dumped_params[0]);
    len += dump_ptr(arm_tracing_ru, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_who, &dumped_params[0]);
    len += dump_rusage(depth-1, arm_tracing_ru, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_umask(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_mask = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_mask, &param_str);
  return param_str;
}

char *dump_sys_prctl(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_option = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_arg2 = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_arg3 = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_arg4 = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_arg5 = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_option, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_arg2, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_arg3, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_arg4, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_arg5, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_getcpu(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_cpup = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_nodep = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_unused = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_cpup, &dumped_params[0]);
    len += dump_ptr(arm_tracing_nodep, &dumped_params[1]);
    len += dump_ptr(arm_tracing_unused, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_cpup, &dumped_params[0], target);
    len += dump_unsigned_int_from_mem(arm_tracing_nodep, &dumped_params[1], target);
    len += dump_getcpu_cache(depth-1, arm_tracing_unused, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_timer_create(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which_clock = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_timer_event_spec = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_created_timer_id = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_ptr(arm_tracing_timer_event_spec, &dumped_params[1]);
    len += dump_ptr(arm_tracing_created_timer_id, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_sigevent(depth-1, arm_tracing_timer_event_spec, &dumped_params[1], target);
    len += dump_int_from_mem(arm_tracing_created_timer_id, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_timer_gettime(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_timer_id = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_setting = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_timer_id, &dumped_params[0]);
    len += dump_ptr(arm_tracing_setting, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_timer_id, &dumped_params[0]);
    len += dump_itimerspec(depth-1, arm_tracing_setting, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_timer_getoverrun(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_timer_id = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_timer_id, &param_str);
  return param_str;
}

char *dump_sys_timer_settime(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_timer_id = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_new_setting = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_old_setting = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_timer_id, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
    len += dump_ptr(arm_tracing_new_setting, &dumped_params[2]);
    len += dump_ptr(arm_tracing_old_setting, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_timer_id, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
    len += dump_itimerspec(depth-1, arm_tracing_new_setting, &dumped_params[2], target);
    len += dump_itimerspec(depth-1, arm_tracing_old_setting, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_timer_delete(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_timer_id = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_timer_id, &param_str);
  return param_str;
}

char *dump_sys_clock_settime(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which_clock = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_tp = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_ptr(arm_tracing_tp, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_timespec(depth-1, arm_tracing_tp, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_clock_gettime(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which_clock = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_tp = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_ptr(arm_tracing_tp, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_timespec(depth-1, arm_tracing_tp, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_clock_adjtime(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which_clock = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_utx = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_ptr(arm_tracing_utx, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_timex(depth-1, arm_tracing_utx, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_clock_getres(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which_clock = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_tp = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_ptr(arm_tracing_tp, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_timespec(depth-1, arm_tracing_tp, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_clock_nanosleep(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which_clock = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_rqtp = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_rmtp = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
    len += dump_ptr(arm_tracing_rqtp, &dumped_params[2]);
    len += dump_ptr(arm_tracing_rmtp, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_which_clock, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
    len += dump_timespec(depth-1, arm_tracing_rqtp, &dumped_params[2], target);
    len += dump_timespec(depth-1, arm_tracing_rmtp, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_ni_syscall(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_nanosleep(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_rqtp = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_rmtp = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_rqtp, &dumped_params[0]);
    len += dump_ptr(arm_tracing_rmtp, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_timespec(depth-1, arm_tracing_rqtp, &dumped_params[0], target);
    len += dump_timespec(depth-1, arm_tracing_rmtp, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setns(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_nstype = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_nstype, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_getgroups(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_gidsetsize = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_grouplist = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_gidsetsize, &dumped_params[0]);
    len += dump_ptr(arm_tracing_grouplist, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_gidsetsize, &dumped_params[0]);
    len += dump_unsigned_int_from_mem(arm_tracing_grouplist, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setgroups(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_gidsetsize = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_grouplist = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_gidsetsize, &dumped_params[0]);
    len += dump_ptr(arm_tracing_grouplist, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_gidsetsize, &dumped_params[0]);
    len += dump_unsigned_int_from_mem(arm_tracing_grouplist, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_set_robust_list(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_head = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_head, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_robust_list_head(depth-1, arm_tracing_head, &dumped_params[0], target);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_get_robust_list(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_head_ptr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_len_ptr = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_head_ptr, &dumped_params[1]);
    len += dump_ptr(arm_tracing_len_ptr, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  arm_tracing_head_ptr = read_ptr_from_mem(arm_tracing_head_ptr, target);
  if (depth == 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_head_ptr, &dumped_params[1]);
    len += dump_unsigned_int_from_mem(arm_tracing_len_ptr, &dumped_params[2], target);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 2)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_robust_list_head(depth-2, arm_tracing_head_ptr, &dumped_params[1], target);
    len += dump_unsigned_int_from_mem(arm_tracing_len_ptr, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_futex(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_uaddr = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_op = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_val = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_utime = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_uaddr2 = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_val3 = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_uaddr, &dumped_params[0]);
    len += dump_int(arm_tracing_op, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_val, &dumped_params[2]);
    len += dump_ptr(arm_tracing_utime, &dumped_params[3]);
    len += dump_ptr(arm_tracing_uaddr2, &dumped_params[4]);
    len += dump_unsigned_int(arm_tracing_val3, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_uaddr, &dumped_params[0], target);
    len += dump_int(arm_tracing_op, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_val, &dumped_params[2]);
    len += dump_timespec(depth-1, arm_tracing_utime, &dumped_params[3], target);
    len += dump_unsigned_int_from_mem(arm_tracing_uaddr2, &dumped_params[4], target);
    len += dump_unsigned_int(arm_tracing_val3, &dumped_params[5]);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_chown16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_user = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_group = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_short_unsigned_int(arm_tracing_user, &dumped_params[1]);
    len += dump_short_unsigned_int(arm_tracing_group, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_short_unsigned_int(arm_tracing_user, &dumped_params[1]);
    len += dump_short_unsigned_int(arm_tracing_group, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_lchown16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_user = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_group = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_short_unsigned_int(arm_tracing_user, &dumped_params[1]);
    len += dump_short_unsigned_int(arm_tracing_group, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_short_unsigned_int(arm_tracing_user, &dumped_params[1]);
    len += dump_short_unsigned_int(arm_tracing_group, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_fchown16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_user = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_group = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_short_unsigned_int(arm_tracing_user, &dumped_params[1]);
    len += dump_short_unsigned_int(arm_tracing_group, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_setregid16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_rgid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_egid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_short_unsigned_int(arm_tracing_rgid, &dumped_params[0]);
    len += dump_short_unsigned_int(arm_tracing_egid, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setgid16(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_gid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_short_unsigned_int(arm_tracing_gid, &param_str);
  return param_str;
}

char *dump_sys_setreuid16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ruid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_euid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_short_unsigned_int(arm_tracing_ruid, &dumped_params[0]);
    len += dump_short_unsigned_int(arm_tracing_euid, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setuid16(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_uid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_short_unsigned_int(arm_tracing_uid, &param_str);
  return param_str;
}

char *dump_sys_setresuid16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ruid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_euid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_suid = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_short_unsigned_int(arm_tracing_ruid, &dumped_params[0]);
    len += dump_short_unsigned_int(arm_tracing_euid, &dumped_params[1]);
    len += dump_short_unsigned_int(arm_tracing_suid, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_getresuid16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ruid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_euid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_suid = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_ruid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_euid, &dumped_params[1]);
    len += dump_ptr(arm_tracing_suid, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_short_unsigned_int_from_mem(arm_tracing_ruid, &dumped_params[0], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_euid, &dumped_params[1], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_suid, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_setresgid16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_rgid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_egid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_sgid = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_short_unsigned_int(arm_tracing_rgid, &dumped_params[0]);
    len += dump_short_unsigned_int(arm_tracing_egid, &dumped_params[1]);
    len += dump_short_unsigned_int(arm_tracing_sgid, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_getresgid16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_rgid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_egid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_sgid = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_rgid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_egid, &dumped_params[1]);
    len += dump_ptr(arm_tracing_sgid, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_short_unsigned_int_from_mem(arm_tracing_rgid, &dumped_params[0], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_egid, &dumped_params[1], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_sgid, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_setfsuid16(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_uid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_short_unsigned_int(arm_tracing_uid, &param_str);
  return param_str;
}

char *dump_sys_setfsgid16(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_gid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_short_unsigned_int(arm_tracing_gid, &param_str);
  return param_str;
}

char *dump_sys_getgroups16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_gidsetsize = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_grouplist = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_gidsetsize, &dumped_params[0]);
    len += dump_ptr(arm_tracing_grouplist, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_gidsetsize, &dumped_params[0]);
    len += dump_short_unsigned_int_from_mem(arm_tracing_grouplist, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setgroups16(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_gidsetsize = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_grouplist = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_gidsetsize, &dumped_params[0]);
    len += dump_ptr(arm_tracing_grouplist, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_gidsetsize, &dumped_params[0]);
    len += dump_short_unsigned_int_from_mem(arm_tracing_grouplist, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_getuid16(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_geteuid16(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_getgid16(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_getegid16(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_delete_module(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_name_user = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_name_user, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_name_user, &dumped_params[0], target);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_init_module(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_umod = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_uargs = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_umod, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_ptr(arm_tracing_uargs, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_n_bytes_from_mem(arm_tracing_umod, &dumped_params[0], target, 256);
    len += dump_long_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_str_from_mem(arm_tracing_uargs, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_sync(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_acct(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_name, &param_str);
    return param_str;
  }

  dump_str_from_mem(arm_tracing_name, &param_str, target);
  return param_str;
}

char *dump_sys_kexec_load(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_entry = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_nr_segments = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_segments = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_entry, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_nr_segments, &dumped_params[1]);
    len += dump_ptr(arm_tracing_segments, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_entry, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_nr_segments, &dumped_params[1]);
    len += dump_kexec_segment(depth-1, arm_tracing_segments, &dumped_params[2], target);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_perf_event_open(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_attr_uptr = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_cpu = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_group_fd = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_attr_uptr, &dumped_params[0]);
    len += dump_int(arm_tracing_pid, &dumped_params[1]);
    len += dump_int(arm_tracing_cpu, &dumped_params[2]);
    len += dump_int(arm_tracing_group_fd, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_perf_event_attr(depth-1, arm_tracing_attr_uptr, &dumped_params[0], target);
    len += dump_int(arm_tracing_pid, &dumped_params[1]);
    len += dump_int(arm_tracing_cpu, &dumped_params[2]);
    len += dump_int(arm_tracing_group_fd, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_readahead(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_offset = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_long_long_int(arm_tracing_offset, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_fadvise64_64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_offset = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_advice = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_long_long_int(arm_tracing_offset, &dumped_params[1]);
    len += dump_long_long_int(arm_tracing_len, &dumped_params[2]);
    len += dump_int(arm_tracing_advice, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_remap_file_pages(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_start = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_prot = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_pgoff = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int(arm_tracing_start, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_size, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_prot, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_pgoff, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_madvise(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_start = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len_in = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_behavior = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int(arm_tracing_start, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len_in, &dumped_params[1]);
    len += dump_int(arm_tracing_behavior, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_mincore(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_start = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_vec = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_start, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_ptr(arm_tracing_vec, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_start, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_unsigned_char_from_mem(arm_tracing_vec, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_mlock(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_start = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int(arm_tracing_start, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_munlock(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_start = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int(arm_tracing_start, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_mlockall(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_flags, &param_str);
  return param_str;
}

char *dump_sys_munlockall(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_brk(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_brk = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_long_unsigned_int(arm_tracing_brk, &param_str);
  return param_str;
}

char *dump_sys_mmap_pgoff(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_addr = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_prot = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_pgoff = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int(arm_tracing_addr, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_prot, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[4]);
    len += dump_long_unsigned_int(arm_tracing_pgoff, &dumped_params[5]);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_old_mmap(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_arg = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_arg, &param_str);
    return param_str;
  }

  dump_mmap_arg_struct(depth-1, arm_tracing_arg, &param_str, target);
  return param_str;
}

char *dump_sys_munmap(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_addr = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int(arm_tracing_addr, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_mprotect(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_start = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_prot = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int(arm_tracing_start, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_prot, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_mremap(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_addr = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_old_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_new_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_new_addr = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int(arm_tracing_addr, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_old_len, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_new_len, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_new_addr, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_msync(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_start = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int(arm_tracing_start, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[1]);
    len += dump_int(arm_tracing_flags, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_process_vm_readv(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_lvec = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_liovcnt = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_rvec = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_riovcnt = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_lvec, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_liovcnt, &dumped_params[2]);
    len += dump_ptr(arm_tracing_rvec, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_riovcnt, &dumped_params[4]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_iovec(depth-1, arm_tracing_lvec, &dumped_params[1], target);
    len += dump_long_unsigned_int(arm_tracing_liovcnt, &dumped_params[2]);
    len += dump_iovec(depth-1, arm_tracing_rvec, &dumped_params[3], target);
    len += dump_long_unsigned_int(arm_tracing_riovcnt, &dumped_params[4]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[5]);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_process_vm_writev(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_lvec = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_liovcnt = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_rvec = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_riovcnt = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_lvec, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_liovcnt, &dumped_params[2]);
    len += dump_ptr(arm_tracing_rvec, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_riovcnt, &dumped_params[4]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_pid, &dumped_params[0]);
    len += dump_iovec(depth-1, arm_tracing_lvec, &dumped_params[1], target);
    len += dump_long_unsigned_int(arm_tracing_liovcnt, &dumped_params[2]);
    len += dump_iovec(depth-1, arm_tracing_rvec, &dumped_params[3], target);
    len += dump_long_unsigned_int(arm_tracing_riovcnt, &dumped_params[4]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[5]);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_swapon(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_specialfile = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_swap_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_specialfile, &dumped_params[0]);
    len += dump_int(arm_tracing_swap_flags, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_specialfile, &dumped_params[0], target);
    len += dump_int(arm_tracing_swap_flags, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_swapoff(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_specialfile = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_specialfile, &param_str);
    return param_str;
  }

  dump_str_from_mem(arm_tracing_specialfile, &param_str, target);
  return param_str;
}

char *dump_sys_open(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
    len += dump_int(arm_tracing_mode, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
    len += dump_int(arm_tracing_mode, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_close(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_fd, &param_str);
  return param_str;
}

char *dump_sys_truncate(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_path = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_length = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_path, &dumped_params[0]);
    len += dump_long_int(arm_tracing_length, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_path, &dumped_params[0], target);
    len += dump_long_int(arm_tracing_length, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_ftruncate(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_length = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_length, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_truncate64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_path = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_length = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_path, &dumped_params[0]);
    len += dump_long_long_int(arm_tracing_length, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_path, &dumped_params[0], target);
    len += dump_long_long_int(arm_tracing_length, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_ftruncate64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_length = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_long_long_int(arm_tracing_length, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_fallocate(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_offset = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_mode, &dumped_params[1]);
    len += dump_long_long_int(arm_tracing_offset, &dumped_params[2]);
    len += dump_long_long_int(arm_tracing_len, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_faccessat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_filename, &dumped_params[1]);
    len += dump_int(arm_tracing_mode, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[1], target);
    len += dump_int(arm_tracing_mode, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_access(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_int(arm_tracing_mode, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_int(arm_tracing_mode, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_chdir(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_filename, &param_str);
    return param_str;
  }

  dump_str_from_mem(arm_tracing_filename, &param_str, target);
  return param_str;
}

char *dump_sys_fchdir(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_fd, &param_str);
  return param_str;
}

char *dump_sys_chroot(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_filename, &param_str);
    return param_str;
  }

  dump_str_from_mem(arm_tracing_filename, &param_str, target);
  return param_str;
}

char *dump_sys_fchmod(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_short_unsigned_int(arm_tracing_mode, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_fchmodat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_filename, &dumped_params[1]);
    len += dump_short_unsigned_int(arm_tracing_mode, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[1], target);
    len += dump_short_unsigned_int(arm_tracing_mode, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_chmod(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_short_unsigned_int(arm_tracing_mode, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_short_unsigned_int(arm_tracing_mode, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_chown(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_user = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_group = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_user, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_group, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_unsigned_int(arm_tracing_user, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_group, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_fchownat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_user = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_group = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_flag = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_filename, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_user, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_group, &dumped_params[3]);
    len += dump_int(arm_tracing_flag, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_user, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_group, &dumped_params[3]);
    len += dump_int(arm_tracing_flag, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_lchown(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_user = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_group = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_user, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_group, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_unsigned_int(arm_tracing_user, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_group, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_fchown(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_user = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_group = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_user, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_group, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_openat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_filename, &dumped_params[1]);
    len += dump_int(arm_tracing_flags, &dumped_params[2]);
    len += dump_int(arm_tracing_mode, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[1], target);
    len += dump_int(arm_tracing_flags, &dumped_params[2]);
    len += dump_int(arm_tracing_mode, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_creat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_int(arm_tracing_mode, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_int(arm_tracing_mode, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_vhangup(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_lseek(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_offset = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_origin = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_long_int(arm_tracing_offset, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_origin, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_llseek(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_offset_high = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_offset_low = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_result = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_origin = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_offset_high, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_offset_low, &dumped_params[2]);
    len += dump_ptr(arm_tracing_result, &dumped_params[3]);
    len += dump_unsigned_int(arm_tracing_origin, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_offset_high, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_offset_low, &dumped_params[2]);
    len += dump_long_long_int_from_mem(arm_tracing_result, &dumped_params[3], target);
    len += dump_unsigned_int(arm_tracing_origin, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_read(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_buf, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_write(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_buf, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);

  return param_str;
}

char *dump_sys_pread64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_pos = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
    len += dump_long_long_int(arm_tracing_pos, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_buf, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
    len += dump_long_long_int(arm_tracing_pos, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_pwrite64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_pos = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
    len += dump_long_long_int(arm_tracing_pos, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_buf, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
    len += dump_long_long_int(arm_tracing_pos, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_readv(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_vec = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_vlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_vec, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_iovec(depth-1, arm_tracing_vec, &dumped_params[1], target);
    len += dump_long_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_writev(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_vec = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_vlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_vec, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_iovec(depth-1, arm_tracing_vec, &dumped_params[1], target);
    len += dump_long_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_preadv(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_vec = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_vlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_pos_l = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_pos_h = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_vec, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_pos_l, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_pos_h, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_iovec(depth-1, arm_tracing_vec, &dumped_params[1], target);
    len += dump_long_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_pos_l, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_pos_h, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_pwritev(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_vec = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_vlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_pos_l = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_pos_h = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_vec, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_pos_l, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_pos_h, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_iovec(depth-1, arm_tracing_vec, &dumped_params[1], target);
    len += dump_long_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_pos_l, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_pos_h, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_sendfile(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_out_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_in_fd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_offset = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_out_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_in_fd, &dumped_params[1]);
    len += dump_ptr(arm_tracing_offset, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_out_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_in_fd, &dumped_params[1]);
    len += dump_long_int_from_mem(arm_tracing_offset, &dumped_params[2], target);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_sendfile64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_out_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_in_fd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_offset = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_out_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_in_fd, &dumped_params[1]);
    len += dump_ptr(arm_tracing_offset, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_out_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_in_fd, &dumped_params[1]);
    len += dump_long_long_int_from_mem(arm_tracing_offset, &dumped_params[2], target);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_newstat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_stat(depth-1, arm_tracing_statbuf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_newlstat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_stat(depth-1, arm_tracing_statbuf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_newfstat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_stat(depth-1, arm_tracing_statbuf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_readlinkat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_bufsiz = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_pathname, &dumped_params[1]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[2]);
    len += dump_int(arm_tracing_bufsiz, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[1], target);
    len += dump_str_from_mem(arm_tracing_buf, &dumped_params[2], target);
    len += dump_int(arm_tracing_bufsiz, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_readlink(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_path = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_bufsiz = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_path, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[1]);
    len += dump_int(arm_tracing_bufsiz, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_path, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_buf, &dumped_params[1], target);
    len += dump_int(arm_tracing_bufsiz, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_stat64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_stat64(depth-1, arm_tracing_statbuf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_lstat64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_stat64(depth-1, arm_tracing_statbuf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_fstat64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_stat64(depth-1, arm_tracing_statbuf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_fstatat64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_statbuf = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flag = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_filename, &dumped_params[1]);
    len += dump_ptr(arm_tracing_statbuf, &dumped_params[2]);
    len += dump_int(arm_tracing_flag, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[1], target);
    len += dump_stat64(depth-1, arm_tracing_statbuf, &dumped_params[2], target);
    len += dump_int(arm_tracing_flag, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_uselib(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_library = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_library, &param_str);
    return param_str;
  }

  dump_str_from_mem(arm_tracing_library, &param_str, target);
  return param_str;
}

char *dump_sys_pipe2(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fildes = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_fildes, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int_from_mem(arm_tracing_fildes, &dumped_params[0], target);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_pipe(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fildes = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_fildes, &param_str);
    return param_str;
  }

  dump_int_from_mem(arm_tracing_fildes, &param_str, target);
  return param_str;
}

char *dump_sys_mknodat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_dev = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_filename, &dumped_params[1]);
    len += dump_int(arm_tracing_mode, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_dev, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[1], target);
    len += dump_int(arm_tracing_mode, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_dev, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_mknod(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_dev = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_int(arm_tracing_mode, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_dev, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_int(arm_tracing_mode, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_dev, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_mkdirat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_pathname, &dumped_params[1]);
    len += dump_int(arm_tracing_mode, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[1], target);
    len += dump_int(arm_tracing_mode, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_mkdir(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_int(arm_tracing_mode, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_int(arm_tracing_mode, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_rmdir(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_pathname, &param_str);
    return param_str;
  }

  dump_str_from_mem(arm_tracing_pathname, &param_str, target);
  return param_str;
}

char *dump_sys_unlinkat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_flag = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_pathname, &dumped_params[1]);
    len += dump_int(arm_tracing_flag, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[1], target);
    len += dump_int(arm_tracing_flag, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_unlink(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_pathname, &param_str);
    return param_str;
  }

  dump_str_from_mem(arm_tracing_pathname, &param_str, target);
  return param_str;
}

char *dump_sys_symlinkat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_oldname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_newdfd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_newname = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_oldname, &dumped_params[0]);
    len += dump_int(arm_tracing_newdfd, &dumped_params[1]);
    len += dump_ptr(arm_tracing_newname, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_oldname, &dumped_params[0], target);
    len += dump_int(arm_tracing_newdfd, &dumped_params[1]);
    len += dump_str_from_mem(arm_tracing_newname, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_symlink(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_oldname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_newname = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_oldname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_newname, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_oldname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_newname, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_linkat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_olddfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_oldname = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_newdfd = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_newname = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_olddfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_oldname, &dumped_params[1]);
    len += dump_int(arm_tracing_newdfd, &dumped_params[2]);
    len += dump_ptr(arm_tracing_newname, &dumped_params[3]);
    len += dump_int(arm_tracing_flags, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_olddfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_oldname, &dumped_params[1], target);
    len += dump_int(arm_tracing_newdfd, &dumped_params[2]);
    len += dump_str_from_mem(arm_tracing_newname, &dumped_params[3], target);
    len += dump_int(arm_tracing_flags, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_link(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_oldname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_newname = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_oldname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_newname, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_oldname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_newname, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_renameat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_olddfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_oldname = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_newdfd = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_newname = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_olddfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_oldname, &dumped_params[1]);
    len += dump_int(arm_tracing_newdfd, &dumped_params[2]);
    len += dump_ptr(arm_tracing_newname, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_olddfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_oldname, &dumped_params[1], target);
    len += dump_int(arm_tracing_newdfd, &dumped_params[2]);
    len += dump_str_from_mem(arm_tracing_newname, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_rename(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_oldname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_newname = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_oldname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_newname, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_oldname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_newname, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_dup3(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_oldfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_newfd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_oldfd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_newfd, &dumped_params[1]);
    len += dump_int(arm_tracing_flags, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_dup2(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_oldfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_newfd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_oldfd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_newfd, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_dup(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fildes = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_fildes, &param_str);
  return param_str;
}

char *dump_sys_fcntl(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_cmd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_arg = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_cmd, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_arg, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_fcntl64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_cmd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_arg = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_cmd, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_arg, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_ioctl(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_cmd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_arg = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_cmd, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_arg, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_old_readdir(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_dirent = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_dirent, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_old_linux_dirent(depth-1, arm_tracing_dirent, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_getdents(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_dirent = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_dirent, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_linux_dirent(depth-1, arm_tracing_dirent, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_getdents64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_dirent = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_dirent, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_linux_dirent64(depth-1, arm_tracing_dirent, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_select(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_n = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_inp = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_outp = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_exp = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_tvp = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_n, &dumped_params[0]);
    len += dump_ptr(arm_tracing_inp, &dumped_params[1]);
    len += dump_ptr(arm_tracing_outp, &dumped_params[2]);
    len += dump_ptr(arm_tracing_exp, &dumped_params[3]);
    len += dump_ptr(arm_tracing_tvp, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_n, &dumped_params[0]);
    len += dump_long_unsigned_int_from_mem(arm_tracing_inp, &dumped_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_outp, &dumped_params[2], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_exp, &dumped_params[3], target);
    len += dump_timeval(depth-1, arm_tracing_tvp, &dumped_params[4], target);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_pselect6(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_n = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_inp = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_outp = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_exp = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_tsp = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_sig = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_n, &dumped_params[0]);
    len += dump_ptr(arm_tracing_inp, &dumped_params[1]);
    len += dump_ptr(arm_tracing_outp, &dumped_params[2]);
    len += dump_ptr(arm_tracing_exp, &dumped_params[3]);
    len += dump_ptr(arm_tracing_tsp, &dumped_params[4]);
    len += dump_ptr(arm_tracing_sig, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_n, &dumped_params[0]);
    len += dump_long_unsigned_int_from_mem(arm_tracing_inp, &dumped_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_outp, &dumped_params[2], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_exp, &dumped_params[3], target);
    len += dump_timespec(depth-1, arm_tracing_tsp, &dumped_params[4], target);
    len += dump_n_bytes_from_mem(arm_tracing_sig, &dumped_params[5], target, 256);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_old_select(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_arg = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_arg, &param_str);
    return param_str;
  }

  dump_sel_arg_struct(depth-1, arm_tracing_arg, &param_str, target);
  return param_str;
}

char *dump_sys_poll(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ufds = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_nfds = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_timeout_msecs = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_ufds, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_nfds, &dumped_params[1]);
    len += dump_long_int(arm_tracing_timeout_msecs, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_pollfd(depth-1, arm_tracing_ufds, &dumped_params[0], target);
    len += dump_unsigned_int(arm_tracing_nfds, &dumped_params[1]);
    len += dump_long_int(arm_tracing_timeout_msecs, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_ppoll(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ufds = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_nfds = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_tsp = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_sigmask = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_sigsetsize = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_ufds, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_nfds, &dumped_params[1]);
    len += dump_ptr(arm_tracing_tsp, &dumped_params[2]);
    len += dump_ptr(arm_tracing_sigmask, &dumped_params[3]);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_pollfd(depth-1, arm_tracing_ufds, &dumped_params[0], target);
    len += dump_unsigned_int(arm_tracing_nfds, &dumped_params[1]);
    len += dump_timespec(depth-1, arm_tracing_tsp, &dumped_params[2], target);
    len += dump_sigset_t(depth-1, arm_tracing_sigmask, &dumped_params[3], target);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_getcwd(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_buf, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_size, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_buf, &dumped_params[0], target);
    len += dump_long_unsigned_int(arm_tracing_size, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_sysfs(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_option = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_arg1 = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_arg2 = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_option, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_arg1, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_arg2, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_umount(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_name, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[0], target);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_oldumount(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_name, &param_str);
    return param_str;
  }

  dump_str_from_mem(arm_tracing_name, &param_str, target);
  return param_str;
}

char *dump_sys_mount(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dev_name = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_dir_name = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_type = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_data = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_dev_name, &dumped_params[0]);
    len += dump_ptr(arm_tracing_dir_name, &dumped_params[1]);
    len += dump_ptr(arm_tracing_type, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_ptr(arm_tracing_data, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_dev_name, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_dir_name, &dumped_params[1], target);
    len += dump_str_from_mem(arm_tracing_type, &dumped_params[2], target);
    len += dump_long_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_n_bytes_from_mem(arm_tracing_data, &dumped_params[4], target, 256);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_pivot_root(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_new_root = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_put_old = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_new_root, &dumped_params[0]);
    len += dump_ptr(arm_tracing_put_old, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_new_root, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_put_old, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_setxattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_value = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_name, &dumped_params[1]);
    len += dump_ptr(arm_tracing_value, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
    len += dump_int(arm_tracing_flags, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[1], target);
    len += dump_n_bytes_from_mem(arm_tracing_value, &dumped_params[2], target, 256);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
    len += dump_int(arm_tracing_flags, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_lsetxattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_value = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_name, &dumped_params[1]);
    len += dump_ptr(arm_tracing_value, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
    len += dump_int(arm_tracing_flags, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[1], target);
    len += dump_n_bytes_from_mem(arm_tracing_value, &dumped_params[2], target, 256);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
    len += dump_int(arm_tracing_flags, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_fsetxattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_value = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_name, &dumped_params[1]);
    len += dump_ptr(arm_tracing_value, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
    len += dump_int(arm_tracing_flags, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[1], target);
    len += dump_n_bytes_from_mem(arm_tracing_value, &dumped_params[2], target, 256);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
    len += dump_int(arm_tracing_flags, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_getxattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_value = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_name, &dumped_params[1]);
    len += dump_ptr(arm_tracing_value, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[1], target);
    len += dump_n_bytes_from_mem(arm_tracing_value, &dumped_params[2], target, 256);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_lgetxattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_value = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_name, &dumped_params[1]);
    len += dump_ptr(arm_tracing_value, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[1], target);
    len += dump_n_bytes_from_mem(arm_tracing_value, &dumped_params[2], target, 256);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_fgetxattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_value = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_name, &dumped_params[1]);
    len += dump_ptr(arm_tracing_value, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[1], target);
    len += dump_n_bytes_from_mem(arm_tracing_value, &dumped_params[2], target, 256);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_listxattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_list = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_list, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_list, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_llistxattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_list = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_list, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_list, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_flistxattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_list = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_list, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_list, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_removexattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_name, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_lremovexattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_name, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_fremovexattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_name = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_name, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_name, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_vmsplice(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_iov = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_nr_segs = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_iov, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_nr_segs, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_iovec(depth-1, arm_tracing_iov, &dumped_params[1], target);
    len += dump_long_unsigned_int(arm_tracing_nr_segs, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_splice(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd_in = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_off_in = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_fd_out = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_off_out = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd_in, &dumped_params[0]);
    len += dump_ptr(arm_tracing_off_in, &dumped_params[1]);
    len += dump_int(arm_tracing_fd_out, &dumped_params[2]);
    len += dump_ptr(arm_tracing_off_out, &dumped_params[3]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[4]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd_in, &dumped_params[0]);
    len += dump_long_long_int_from_mem(arm_tracing_off_in, &dumped_params[1], target);
    len += dump_int(arm_tracing_fd_out, &dumped_params[2]);
    len += dump_long_long_int_from_mem(arm_tracing_off_out, &dumped_params[3], target);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[4]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[5]);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_tee(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fdin = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_fdout = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fdin, &dumped_params[0]);
    len += dump_int(arm_tracing_fdout, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_syncfs(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_fd, &param_str);
  return param_str;
}

char *dump_sys_fsync(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_fd, &param_str);
  return param_str;
}

char *dump_sys_fdatasync(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_fd, &param_str);
  return param_str;
}

char *dump_sys_sync_file_range(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_offset = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_nbytes = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_long_long_int(arm_tracing_offset, &dumped_params[1]);
    len += dump_long_long_int(arm_tracing_nbytes, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_sync_file_range2(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_offset = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_nbytes = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[1]);
    len += dump_long_long_int(arm_tracing_offset, &dumped_params[2]);
    len += dump_long_long_int(arm_tracing_nbytes, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_utime(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_times = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_ptr(arm_tracing_times, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_utimbuf(depth-1, arm_tracing_times, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_utimensat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_utimes = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_filename, &dumped_params[1]);
    len += dump_ptr(arm_tracing_utimes, &dumped_params[2]);
    len += dump_int(arm_tracing_flags, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[1], target);
    len += dump_timespec(depth-1, arm_tracing_utimes, &dumped_params[2], target);
    len += dump_int(arm_tracing_flags, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_futimesat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_utimes = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_filename, &dumped_params[1]);
    len += dump_ptr(arm_tracing_utimes, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_dfd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[1], target);
    len += dump_timeval(depth-1, arm_tracing_utimes, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_utimes(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_filename = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_utimes = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_filename, &dumped_params[0]);
    len += dump_ptr(arm_tracing_utimes, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_filename, &dumped_params[0], target);
    len += dump_timeval(depth-1, arm_tracing_utimes, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_statfs(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_statfs(depth-1, arm_tracing_buf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_statfs64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_sz = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_pathname, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_sz, &dumped_params[1]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[0], target);
    len += dump_unsigned_int(arm_tracing_sz, &dumped_params[1]);
    len += dump_statfs64(depth-1, arm_tracing_buf, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_fstatfs(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_statfs(depth-1, arm_tracing_buf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_fstatfs64(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_sz = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_sz, &dumped_params[1]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_sz, &dumped_params[1]);
    len += dump_statfs64(depth-1, arm_tracing_buf, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_ustat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_dev = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_ubuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_dev, &dumped_params[0]);
    len += dump_ptr(arm_tracing_ubuf, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_dev, &dumped_params[0]);
    len += dump_ustat(depth-1, arm_tracing_ubuf, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_bdflush(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_func = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_data = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_func, &dumped_params[0]);
    len += dump_long_int(arm_tracing_data, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_ioprio_set(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_who = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_ioprio = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_which, &dumped_params[0]);
    len += dump_int(arm_tracing_who, &dumped_params[1]);
    len += dump_int(arm_tracing_ioprio, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_ioprio_get(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_which = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_who = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_which, &dumped_params[0]);
    len += dump_int(arm_tracing_who, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_inotify_init1(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_flags, &param_str);
  return param_str;
}

char *dump_sys_inotify_init(int depth, struct target *target)
{
  char *param_str = malloc(5);
  snprintf(param_str, 5, "void");
  return param_str;
}

char *dump_sys_inotify_add_watch(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_pathname = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_mask = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_pathname, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_mask, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_pathname, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_mask, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_inotify_rm_watch(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_wd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_wd, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_epoll_create1(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_flags, &param_str);
  return param_str;
}

char *dump_sys_epoll_create(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_int(arm_tracing_size, &param_str);
  return param_str;
}

char *dump_sys_epoll_ctl(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_epfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_op = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_event = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_epfd, &dumped_params[0]);
    len += dump_int(arm_tracing_op, &dumped_params[1]);
    len += dump_int(arm_tracing_fd, &dumped_params[2]);
    len += dump_ptr(arm_tracing_event, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_epfd, &dumped_params[0]);
    len += dump_int(arm_tracing_op, &dumped_params[1]);
    len += dump_int(arm_tracing_fd, &dumped_params[2]);
    len += dump_epoll_event(depth-1, arm_tracing_event, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_epoll_wait(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_epfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_events = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_maxevents = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_timeout = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_epfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_events, &dumped_params[1]);
    len += dump_int(arm_tracing_maxevents, &dumped_params[2]);
    len += dump_int(arm_tracing_timeout, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_epfd, &dumped_params[0]);
    len += dump_epoll_event(depth-1, arm_tracing_events, &dumped_params[1], target);
    len += dump_int(arm_tracing_maxevents, &dumped_params[2]);
    len += dump_int(arm_tracing_timeout, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_epoll_pwait(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_epfd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_events = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_maxevents = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_timeout = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_sigmask = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_sigsetsize = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_epfd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_events, &dumped_params[1]);
    len += dump_int(arm_tracing_maxevents, &dumped_params[2]);
    len += dump_int(arm_tracing_timeout, &dumped_params[3]);
    len += dump_ptr(arm_tracing_sigmask, &dumped_params[4]);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_epfd, &dumped_params[0]);
    len += dump_epoll_event(depth-1, arm_tracing_events, &dumped_params[1], target);
    len += dump_int(arm_tracing_maxevents, &dumped_params[2]);
    len += dump_int(arm_tracing_timeout, &dumped_params[3]);
    len += dump_sigset_t(depth-1, arm_tracing_sigmask, &dumped_params[4], target);
    len += dump_unsigned_int(arm_tracing_sigsetsize, &dumped_params[5]);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_signalfd4(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ufd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_user_mask = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_sizemask = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_ufd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_user_mask, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_sizemask, &dumped_params[2]);
    len += dump_int(arm_tracing_flags, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_ufd, &dumped_params[0]);
    len += dump_sigset_t(depth-1, arm_tracing_user_mask, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_sizemask, &dumped_params[2]);
    len += dump_int(arm_tracing_flags, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_signalfd(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ufd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_user_mask = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_sizemask = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_ufd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_user_mask, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_sizemask, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_ufd, &dumped_params[0]);
    len += dump_sigset_t(depth-1, arm_tracing_user_mask, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_sizemask, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_timerfd_create(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_clockid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_clockid, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_timerfd_settime(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ufd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_utmr = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_otmr = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_ufd, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
    len += dump_ptr(arm_tracing_utmr, &dumped_params[2]);
    len += dump_ptr(arm_tracing_otmr, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_ufd, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
    len += dump_itimerspec(depth-1, arm_tracing_utmr, &dumped_params[2], target);
    len += dump_itimerspec(depth-1, arm_tracing_otmr, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_timerfd_gettime(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ufd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_otmr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_ufd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_otmr, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_ufd, &dumped_params[0]);
    len += dump_itimerspec(depth-1, arm_tracing_otmr, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_eventfd2(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_count, &dumped_params[0]);
    len += dump_int(arm_tracing_flags, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_eventfd(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_count = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_unsigned_int(arm_tracing_count, &param_str);
  return param_str;
}

char *dump_sys_io_setup(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_nr_events = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_ctxp = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_nr_events, &dumped_params[0]);
    len += dump_ptr(arm_tracing_ctxp, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_nr_events, &dumped_params[0]);
    len += dump_long_unsigned_int_from_mem(arm_tracing_ctxp, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_io_destroy(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ctx = get_uint32_t_register_by_name(target->reg_cache, "r0");
  dump_long_unsigned_int(arm_tracing_ctx, &param_str);
  return param_str;
}

char *dump_sys_io_submit(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ctx_id = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_nr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_iocbpp = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_ctx_id, &dumped_params[0]);
    len += dump_long_int(arm_tracing_nr, &dumped_params[1]);
    len += dump_ptr(arm_tracing_iocbpp, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  arm_tracing_iocbpp = read_ptr_from_mem(arm_tracing_iocbpp, target);
  if (depth == 1)
  {
    len += dump_long_unsigned_int(arm_tracing_ctx_id, &dumped_params[0]);
    len += dump_long_int(arm_tracing_nr, &dumped_params[1]);
    len += dump_ptr(arm_tracing_iocbpp, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 2)
  {
    len += dump_long_unsigned_int(arm_tracing_ctx_id, &dumped_params[0]);
    len += dump_long_int(arm_tracing_nr, &dumped_params[1]);
    len += dump_iocb(depth-2, arm_tracing_iocbpp, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_io_cancel(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ctx_id = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_iocb = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_result = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_ctx_id, &dumped_params[0]);
    len += dump_ptr(arm_tracing_iocb, &dumped_params[1]);
    len += dump_ptr(arm_tracing_result, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_ctx_id, &dumped_params[0]);
    len += dump_iocb(depth-1, arm_tracing_iocb, &dumped_params[1], target);
    len += dump_io_event(depth-1, arm_tracing_result, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_io_getevents(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_ctx_id = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_min_nr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_nr = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_events = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_timeout = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_unsigned_int(arm_tracing_ctx_id, &dumped_params[0]);
    len += dump_long_int(arm_tracing_min_nr, &dumped_params[1]);
    len += dump_long_int(arm_tracing_nr, &dumped_params[2]);
    len += dump_ptr(arm_tracing_events, &dumped_params[3]);
    len += dump_ptr(arm_tracing_timeout, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int(arm_tracing_ctx_id, &dumped_params[0]);
    len += dump_long_int(arm_tracing_min_nr, &dumped_params[1]);
    len += dump_long_int(arm_tracing_nr, &dumped_params[2]);
    len += dump_io_event(depth-1, arm_tracing_events, &dumped_params[3], target);
    len += dump_timespec(depth-1, arm_tracing_timeout, &dumped_params[4], target);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_flock(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_cmd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_cmd, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_quotactl(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_cmd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_special = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_id = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_addr = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_cmd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_special, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_id, &dumped_params[2]);
    len += dump_ptr(arm_tracing_addr, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_cmd, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_special, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_id, &dumped_params[2]);
    len += dump_n_bytes_from_mem(arm_tracing_addr, &dumped_params[3], target, 256);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_lookup_dcookie(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_cookie64 = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_long_long_unsigned_int(arm_tracing_cookie64, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_long_long_unsigned_int(arm_tracing_cookie64, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_buf, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_msgget(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_key = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_msgflg = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_key, &dumped_params[0]);
    len += dump_int(arm_tracing_msgflg, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_msgsnd(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_msqid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_msgp = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_msgsz = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_msgflg = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_msqid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_msgp, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_msgsz, &dumped_params[2]);
    len += dump_int(arm_tracing_msgflg, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_msqid, &dumped_params[0]);
    len += dump_msgbuf(depth-1, arm_tracing_msgp, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_msgsz, &dumped_params[2]);
    len += dump_int(arm_tracing_msgflg, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_msgrcv(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_msqid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_msgp = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_msgsz = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_msgtyp = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_msgflg = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_msqid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_msgp, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_msgsz, &dumped_params[2]);
    len += dump_long_int(arm_tracing_msgtyp, &dumped_params[3]);
    len += dump_int(arm_tracing_msgflg, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_msqid, &dumped_params[0]);
    len += dump_msgbuf(depth-1, arm_tracing_msgp, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_msgsz, &dumped_params[2]);
    len += dump_long_int(arm_tracing_msgtyp, &dumped_params[3]);
    len += dump_int(arm_tracing_msgflg, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_semget(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_key = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_nsems = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_semflg = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_key, &dumped_params[0]);
    len += dump_int(arm_tracing_nsems, &dumped_params[1]);
    len += dump_int(arm_tracing_semflg, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_semctl(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_semid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_semnum = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_cmd = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_arg = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_semid, &dumped_params[0]);
    len += dump_int(arm_tracing_semnum, &dumped_params[1]);
    len += dump_int(arm_tracing_cmd, &dumped_params[2]);
    len += dump_n_bytes_from_mem(arm_tracing_arg, &dumped_params[3], target, 4);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_semtimedop(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_semid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_tsops = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_nsops = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_timeout = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_semid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_tsops, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_nsops, &dumped_params[2]);
    len += dump_ptr(arm_tracing_timeout, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_semid, &dumped_params[0]);
    len += dump_sembuf(depth-1, arm_tracing_tsops, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_nsops, &dumped_params[2]);
    len += dump_timespec(depth-1, arm_tracing_timeout, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_semop(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_semid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_tsops = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_nsops = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_semid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_tsops, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_nsops, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_semid, &dumped_params[0]);
    len += dump_sembuf(depth-1, arm_tracing_tsops, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_nsops, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_shmget(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_key = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_shmflg = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_key, &dumped_params[0]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[1]);
    len += dump_int(arm_tracing_shmflg, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_shmctl(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_shmid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_cmd = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_buf = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_shmid, &dumped_params[0]);
    len += dump_int(arm_tracing_cmd, &dumped_params[1]);
    len += dump_ptr(arm_tracing_buf, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_shmid, &dumped_params[0]);
    len += dump_int(arm_tracing_cmd, &dumped_params[1]);
    len += dump_shmid_ds(depth-1, arm_tracing_buf, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_shmat(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_shmid = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_shmaddr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_shmflg = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_shmid, &dumped_params[0]);
    len += dump_ptr(arm_tracing_shmaddr, &dumped_params[1]);
    len += dump_int(arm_tracing_shmflg, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_shmid, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_shmaddr, &dumped_params[1], target);
    len += dump_int(arm_tracing_shmflg, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_shmdt(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_shmaddr = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_shmaddr, &param_str);
    return param_str;
  }

  dump_str_from_mem(arm_tracing_shmaddr, &param_str, target);
  return param_str;
}

char *dump_sys_ipc(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_call = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_first = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_second = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_third = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_ptr = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_fifth = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_unsigned_int(arm_tracing_call, &dumped_params[0]);
    len += dump_int(arm_tracing_first, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_second, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_third, &dumped_params[3]);
    len += dump_ptr(arm_tracing_ptr, &dumped_params[4]);
    len += dump_long_int(arm_tracing_fifth, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_unsigned_int(arm_tracing_call, &dumped_params[0]);
    len += dump_int(arm_tracing_first, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_second, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_third, &dumped_params[3]);
    len += dump_n_bytes_from_mem(arm_tracing_ptr, &dumped_params[4], target, 256);
    len += dump_long_int(arm_tracing_fifth, &dumped_params[5]);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_mq_open(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_u_name = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_oflag = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_mode = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_u_attr = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_u_name, &dumped_params[0]);
    len += dump_int(arm_tracing_oflag, &dumped_params[1]);
    len += dump_short_unsigned_int(arm_tracing_mode, &dumped_params[2]);
    len += dump_ptr(arm_tracing_u_attr, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing_u_name, &dumped_params[0], target);
    len += dump_int(arm_tracing_oflag, &dumped_params[1]);
    len += dump_short_unsigned_int(arm_tracing_mode, &dumped_params[2]);
    len += dump_mq_attr(depth-1, arm_tracing_u_attr, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_mq_unlink(int depth, struct target *target)
{
  char *param_str;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_u_name = get_uint32_t_register_by_name(target->reg_cache, "r0");
  if (depth == 0)
  {
    dump_ptr(arm_tracing_u_name, &param_str);
    return param_str;
  }

  dump_str_from_mem(arm_tracing_u_name, &param_str, target);
  return param_str;
}

char *dump_sys_mq_timedsend(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_mqdes = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_u_msg_ptr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_msg_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_msg_prio = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_u_abs_timeout = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_mqdes, &dumped_params[0]);
    len += dump_ptr(arm_tracing_u_msg_ptr, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_msg_len, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_msg_prio, &dumped_params[3]);
    len += dump_ptr(arm_tracing_u_abs_timeout, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_mqdes, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_u_msg_ptr, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_msg_len, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_msg_prio, &dumped_params[3]);
    len += dump_timespec(depth-1, arm_tracing_u_abs_timeout, &dumped_params[4], target);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_mq_timedreceive(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_mqdes = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_u_msg_ptr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_msg_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_u_msg_prio = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_u_abs_timeout = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_mqdes, &dumped_params[0]);
    len += dump_ptr(arm_tracing_u_msg_ptr, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_msg_len, &dumped_params[2]);
    len += dump_ptr(arm_tracing_u_msg_prio, &dumped_params[3]);
    len += dump_ptr(arm_tracing_u_abs_timeout, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_mqdes, &dumped_params[0]);
    len += dump_str_from_mem(arm_tracing_u_msg_ptr, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_msg_len, &dumped_params[2]);
    len += dump_unsigned_int_from_mem(arm_tracing_u_msg_prio, &dumped_params[3], target);
    len += dump_timespec(depth-1, arm_tracing_u_abs_timeout, &dumped_params[4], target);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_mq_notify(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_mqdes = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_u_notification = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_mqdes, &dumped_params[0]);
    len += dump_ptr(arm_tracing_u_notification, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_mqdes, &dumped_params[0]);
    len += dump_sigevent(depth-1, arm_tracing_u_notification, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_mq_getsetattr(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_mqdes = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_u_mqstat = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_u_omqstat = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_mqdes, &dumped_params[0]);
    len += dump_ptr(arm_tracing_u_mqstat, &dumped_params[1]);
    len += dump_ptr(arm_tracing_u_omqstat, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_mqdes, &dumped_params[0]);
    len += dump_mq_attr(depth-1, arm_tracing_u_mqstat, &dumped_params[1], target);
    len += dump_mq_attr(depth-1, arm_tracing_u_omqstat, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_add_key(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing__type = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing__description = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing__payload = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_plen = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_ringid = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing__type, &dumped_params[0]);
    len += dump_ptr(arm_tracing__description, &dumped_params[1]);
    len += dump_ptr(arm_tracing__payload, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_plen, &dumped_params[3]);
    len += dump_int(arm_tracing_ringid, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing__type, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing__description, &dumped_params[1], target);
    len += dump_n_bytes_from_mem(arm_tracing__payload, &dumped_params[2], target, 256);
    len += dump_unsigned_int(arm_tracing_plen, &dumped_params[3]);
    len += dump_int(arm_tracing_ringid, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_request_key(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing__type = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing__description = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing__callout_info = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_destringid = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing__type, &dumped_params[0]);
    len += dump_ptr(arm_tracing__description, &dumped_params[1]);
    len += dump_ptr(arm_tracing__callout_info, &dumped_params[2]);
    len += dump_int(arm_tracing_destringid, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_str_from_mem(arm_tracing__type, &dumped_params[0], target);
    len += dump_str_from_mem(arm_tracing__description, &dumped_params[1], target);
    len += dump_str_from_mem(arm_tracing__callout_info, &dumped_params[2], target);
    len += dump_int(arm_tracing_destringid, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_keyctl(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_option = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_arg2 = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_arg3 = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_arg4 = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_arg5 = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_option, &dumped_params[0]);
    len += dump_long_unsigned_int(arm_tracing_arg2, &dumped_params[1]);
    len += dump_long_unsigned_int(arm_tracing_arg3, &dumped_params[2]);
    len += dump_long_unsigned_int(arm_tracing_arg4, &dumped_params[3]);
    len += dump_long_unsigned_int(arm_tracing_arg5, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_send(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buff = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buff, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_n_bytes_from_mem(arm_tracing_buff, &dumped_params[1], target, 256);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_recv(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_ubuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_ubuf, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_n_bytes_from_mem(arm_tracing_ubuf, &dumped_params[1], target, 256);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_sendmmsg(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_mmsg = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_vlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_mmsg, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_mmsghdr(depth-1, arm_tracing_mmsg, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_socket(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_family = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_type = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_protocol = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_family, &dumped_params[0]);
    len += dump_int(arm_tracing_type, &dumped_params[1]);
    len += dump_int(arm_tracing_protocol, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_socketpair(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_family = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_type = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_protocol = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_usockvec = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_family, &dumped_params[0]);
    len += dump_int(arm_tracing_type, &dumped_params[1]);
    len += dump_int(arm_tracing_protocol, &dumped_params[2]);
    len += dump_ptr(arm_tracing_usockvec, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_family, &dumped_params[0]);
    len += dump_int(arm_tracing_type, &dumped_params[1]);
    len += dump_int(arm_tracing_protocol, &dumped_params[2]);
    len += dump_int_from_mem(arm_tracing_usockvec, &dumped_params[3], target);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_bind(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_umyaddr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_addrlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_umyaddr, &dumped_params[1]);
    len += dump_int(arm_tracing_addrlen, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_sockaddr(depth-1, arm_tracing_umyaddr, &dumped_params[1], target);
    len += dump_int(arm_tracing_addrlen, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_listen(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_backlog = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_backlog, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_accept4(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_upeer_sockaddr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_upeer_addrlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  dumped_params = malloc(4 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_upeer_sockaddr, &dumped_params[1]);
    len += dump_ptr(arm_tracing_upeer_addrlen, &dumped_params[2]);
    len += dump_int(arm_tracing_flags, &dumped_params[3]);
    param_str = copy_params(dumped_params, 4, &len);
    free_dumped_params(dumped_params, 4);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_sockaddr(depth-1, arm_tracing_upeer_sockaddr, &dumped_params[1], target);
    len += dump_int_from_mem(arm_tracing_upeer_addrlen, &dumped_params[2], target);
    len += dump_int(arm_tracing_flags, &dumped_params[3]);
  }

  param_str = copy_params(dumped_params, 4, &len);
  free_dumped_params(dumped_params, 4);
  return param_str;
}

char *dump_sys_accept(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_upeer_sockaddr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_upeer_addrlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_upeer_sockaddr, &dumped_params[1]);
    len += dump_ptr(arm_tracing_upeer_addrlen, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_sockaddr(depth-1, arm_tracing_upeer_sockaddr, &dumped_params[1], target);
    len += dump_int_from_mem(arm_tracing_upeer_addrlen, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_connect(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_uservaddr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_addrlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_uservaddr, &dumped_params[1]);
    len += dump_int(arm_tracing_addrlen, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_sockaddr(depth-1, arm_tracing_uservaddr, &dumped_params[1], target);
    len += dump_int(arm_tracing_addrlen, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_getsockname(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_usockaddr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_usockaddr_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_usockaddr, &dumped_params[1]);
    len += dump_ptr(arm_tracing_usockaddr_len, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_sockaddr(depth-1, arm_tracing_usockaddr, &dumped_params[1], target);
    len += dump_int_from_mem(arm_tracing_usockaddr_len, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_getpeername(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_usockaddr = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_usockaddr_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_usockaddr, &dumped_params[1]);
    len += dump_ptr(arm_tracing_usockaddr_len, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_sockaddr(depth-1, arm_tracing_usockaddr, &dumped_params[1], target);
    len += dump_int_from_mem(arm_tracing_usockaddr_len, &dumped_params[2], target);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_sendto(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_buff = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_len = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_addr = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_addr_len = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_buff, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_ptr(arm_tracing_addr, &dumped_params[4]);
    len += dump_int(arm_tracing_addr_len, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_n_bytes_from_mem(arm_tracing_buff, &dumped_params[1], target, 256);
    len += dump_unsigned_int(arm_tracing_len, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_sockaddr(depth-1, arm_tracing_addr, &dumped_params[4], target);
    len += dump_int(arm_tracing_addr_len, &dumped_params[5]);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_recvfrom(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_ubuf = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_size = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_addr = get_uint32_t_register_by_name(target->reg_cache, "r4");
  unsigned int arm_tracing_addr_len = get_uint32_t_register_by_name(target->reg_cache, "r5");
  dumped_params = malloc(6 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_ubuf, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_ptr(arm_tracing_addr, &dumped_params[4]);
    len += dump_ptr(arm_tracing_addr_len, &dumped_params[5]);
    param_str = copy_params(dumped_params, 6, &len);
    free_dumped_params(dumped_params, 6);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_n_bytes_from_mem(arm_tracing_ubuf, &dumped_params[1], target, 256);
    len += dump_unsigned_int(arm_tracing_size, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_sockaddr(depth-1, arm_tracing_addr, &dumped_params[4], target);
    len += dump_int_from_mem(arm_tracing_addr_len, &dumped_params[5], target);
  }

  param_str = copy_params(dumped_params, 6, &len);
  free_dumped_params(dumped_params, 6);
  return param_str;
}

char *dump_sys_setsockopt(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_level = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_optname = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_optval = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_optlen = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_level, &dumped_params[1]);
    len += dump_int(arm_tracing_optname, &dumped_params[2]);
    len += dump_ptr(arm_tracing_optval, &dumped_params[3]);
    len += dump_int(arm_tracing_optlen, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_level, &dumped_params[1]);
    len += dump_int(arm_tracing_optname, &dumped_params[2]);
    len += dump_str_from_mem(arm_tracing_optval, &dumped_params[3], target);
    len += dump_int(arm_tracing_optlen, &dumped_params[4]);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_getsockopt(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_level = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_optname = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_optval = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_optlen = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_level, &dumped_params[1]);
    len += dump_int(arm_tracing_optname, &dumped_params[2]);
    len += dump_ptr(arm_tracing_optval, &dumped_params[3]);
    len += dump_ptr(arm_tracing_optlen, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_level, &dumped_params[1]);
    len += dump_int(arm_tracing_optname, &dumped_params[2]);
    len += dump_str_from_mem(arm_tracing_optval, &dumped_params[3], target);
    len += dump_int_from_mem(arm_tracing_optlen, &dumped_params[4], target);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_shutdown(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_how = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_int(arm_tracing_how, &dumped_params[1]);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

char *dump_sys_sendmsg(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_msg = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_msg, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_msghdr(depth-1, arm_tracing_msg, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_recvmsg(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_msg = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r2");
  dumped_params = malloc(3 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_msg, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[2]);
    param_str = copy_params(dumped_params, 3, &len);
    free_dumped_params(dumped_params, 3);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_msghdr(depth-1, arm_tracing_msg, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[2]);
  }

  param_str = copy_params(dumped_params, 3, &len);
  free_dumped_params(dumped_params, 3);
  return param_str;
}

char *dump_sys_recvmmsg(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_fd = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_mmsg = get_uint32_t_register_by_name(target->reg_cache, "r1");
  unsigned int arm_tracing_vlen = get_uint32_t_register_by_name(target->reg_cache, "r2");
  unsigned int arm_tracing_flags = get_uint32_t_register_by_name(target->reg_cache, "r3");
  unsigned int arm_tracing_timeout = get_uint32_t_register_by_name(target->reg_cache, "r4");
  dumped_params = malloc(5 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_ptr(arm_tracing_mmsg, &dumped_params[1]);
    len += dump_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_ptr(arm_tracing_timeout, &dumped_params[4]);
    param_str = copy_params(dumped_params, 5, &len);
    free_dumped_params(dumped_params, 5);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_fd, &dumped_params[0]);
    len += dump_mmsghdr(depth-1, arm_tracing_mmsg, &dumped_params[1], target);
    len += dump_unsigned_int(arm_tracing_vlen, &dumped_params[2]);
    len += dump_unsigned_int(arm_tracing_flags, &dumped_params[3]);
    len += dump_timespec(depth-1, arm_tracing_timeout, &dumped_params[4], target);
  }

  param_str = copy_params(dumped_params, 5, &len);
  free_dumped_params(dumped_params, 5);
  return param_str;
}

char *dump_sys_socketcall(int depth, struct target *target)
{
  char **dumped_params;
  char *param_str;
  int len = 0;
  if (depth < 0)
  {
    param_str = malloc(0);
    return param_str;
  }

  unsigned int arm_tracing_call = get_uint32_t_register_by_name(target->reg_cache, "r0");
  unsigned int arm_tracing_args = get_uint32_t_register_by_name(target->reg_cache, "r1");
  dumped_params = malloc(2 * (sizeof(char *)));
  if (depth == 0)
  {
    len += dump_int(arm_tracing_call, &dumped_params[0]);
    len += dump_ptr(arm_tracing_args, &dumped_params[1]);
    param_str = copy_params(dumped_params, 2, &len);
    free_dumped_params(dumped_params, 2);
    return param_str;
  }

  if (depth >= 1)
  {
    len += dump_int(arm_tracing_call, &dumped_params[0]);
    len += dump_long_unsigned_int_from_mem(arm_tracing_args, &dumped_params[1], target);
  }

  param_str = copy_params(dumped_params, 2, &len);
  free_dumped_params(dumped_params, 2);
  return param_str;
}

int dump_generic(char **param_str, unsigned int size, char *format, unsigned int value)
{
  *param_str = malloc(size);
  int snprintf_n_read = snprintf(*param_str, size, format, value);
  return snprintf_n_read;
}

void free_dumped_params(char **dumped_params, int nr_params)
{
  int i;
  for (i = 0; i < nr_params; i++)
  {
    free(dumped_params[i]);
  }

  free(dumped_params);
}

char *copy_params(char **dumped_params, int nr_params, int *len)
{
  int i;
  int j;
  int aux_len;
  char *merged_params;
  if ((*len) == 0)
  {
    merged_params = malloc(0);
    return merged_params;
  }

  *len += ((1 + nr_params) - 1) + 2;
  merged_params = malloc(*len);
  merged_params[0] = '{';
  for (aux_len = 1, i = 0; i < nr_params; i++)
  {
    for (j = 0; dumped_params[i][j] != '\0'; j++)
      merged_params[aux_len + j] = dumped_params[i][j];

    merged_params[aux_len + j] = ',';
    aux_len += j + 1;
  }

  merged_params[aux_len - 1] = '}';
  merged_params[aux_len] = '\0';
  return merged_params;
}

int dump_str_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  char *buff = malloc(1024);
  char *value;
  int len = 0;
  do
  {
    value = get_address_value(target, addr++, SIZE_OF_CHAR);
    buff[len++] = *value;
    free(value);
  }
  while ((len < 1024) && (*value));
  *param_str = buff;
  return len;
}

unsigned int read_ptr_from_mem(unsigned int addr, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_PTR);
  unsigned int value_of_addr = *value;
  free(value);
  return value_of_addr;
}

int dump_n_bytes_from_mem(unsigned int addr, char **param_str, struct target *target, unsigned int size)
{
  unsigned int pos;
  unsigned int nread = 0;
  char *buff = malloc(size);
  char *value;
  for (pos = 0; (pos < size) && ((nread + 4) < size); pos++)
  {
    value = get_address_value(target, addr++, SIZE_OF_CHAR);
    nread += snprintf(&buff[nread], 4, "%x ", *value);
    free(value);
  }

  *param_str = buff;
  return nread;
}

int dump_int(unsigned int value, char **param_str)
{
  int len = dump_generic(param_str, NUM_CHARS_INT, "%d", value);
  return len;
}

int dump_long_unsigned_int(unsigned int value, char **param_str)
{
  int len = dump_generic(param_str, NUM_CHARS_ULONG, "%lu", value);
  return len;
}

int dump_ptr(unsigned int value, char **param_str)
{
  int len = dump_generic(param_str, NUM_CHARS_PTR, "0x%x", value);
  return len;
}

int dump_long_unsigned_int_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_ULONG);
  int snprintf_n_read = dump_generic(param_str, NUM_CHARS_ULONG, "%lu", *value);
  free(value);
  return snprintf_n_read;
}

int dump_old_sigaction(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_sa_handler = addr;
  unsigned int arm_tracing_sa_mask = addr+4;
  unsigned int arm_tracing_sa_flags = addr+8;
  unsigned int arm_tracing_sa_restorer = addr+12;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_ptr(arm_tracing_sa_handler, &dumped_params[0]);
    len += dump_long_unsigned_int_from_mem(arm_tracing_sa_mask, &dumped_type_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_sa_flags, &dumped_type_params[2], target);
    len += dump_ptr(arm_tracing_sa_restorer, &dumped_params[3]);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_pt_regs(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_uregs = addr;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(1 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int_from_mem(arm_tracing_uregs, &dumped_type_params[0], target);
  }

  *dumped_params = copy_params(dumped_type_params, 1, &len);
  free_dumped_params(dumped_type_params, 1);
  return len;
}

int dump_int_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_INT);
  int snprintf_n_read = dump_generic(param_str, NUM_CHARS_INT, "%d", *value);
  free(value);
  return snprintf_n_read;
}

int dump_long_long_int(unsigned int value, char **param_str)
{
  int len = dump_generic(param_str, NUM_CHARS_LONG_LONG, "%lli", value);
  return len;
}

int dump_long_long_unsigned_int_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_LONG_LONG);
  int snprintf_n_read = dump_generic(param_str, NUM_CHARS_LONG_LONG, "%llu", *value);
  free(value);
  return snprintf_n_read;
}

int dump_unsigned_int_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_UINT);
  int snprintf_n_read = dump_generic(param_str, NUM_CHARS_UINT, "%u", *value);
  free(value);
  return snprintf_n_read;
}

int dump_long_long_int_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_LONG_LONG);
  int snprintf_n_read = dump_generic(param_str, NUM_CHARS_LONG_LONG, "%lli", *value);
  free(value);
  return snprintf_n_read;
}

int dump_oldabi_stat64(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_st_dev = addr;
  unsigned int arm_tracing___pad1 = addr+8;
  unsigned int arm_tracing___st_ino = addr+12;
  unsigned int arm_tracing_st_mode = addr+16;
  unsigned int arm_tracing_st_nlink = addr+20;
  unsigned int arm_tracing_st_uid = addr+24;
  unsigned int arm_tracing_st_gid = addr+28;
  unsigned int arm_tracing_st_rdev = addr+32;
  unsigned int arm_tracing___pad2 = addr+40;
  unsigned int arm_tracing_st_size = addr+44;
  unsigned int arm_tracing_st_blksize = addr+52;
  unsigned int arm_tracing_st_blocks = addr+56;
  unsigned int arm_tracing_st_atime = addr+64;
  unsigned int arm_tracing_st_atime_nsec = addr+68;
  unsigned int arm_tracing_st_mtime = addr+72;
  unsigned int arm_tracing_st_mtime_nsec = addr+76;
  unsigned int arm_tracing_st_ctime = addr+80;
  unsigned int arm_tracing_st_ctime_nsec = addr+84;
  unsigned int arm_tracing_st_ino = addr+88;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(19 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_st_dev, &dumped_type_params[0], target);
    len += dump_unsigned_int_from_mem(arm_tracing___pad1, &dumped_type_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing___st_ino, &dumped_type_params[2], target);
    len += dump_unsigned_int_from_mem(arm_tracing_st_mode, &dumped_type_params[3], target);
    len += dump_unsigned_int_from_mem(arm_tracing_st_nlink, &dumped_type_params[4], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_uid, &dumped_type_params[5], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_gid, &dumped_type_params[6], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_st_rdev, &dumped_type_params[7], target);
    len += dump_unsigned_int_from_mem(arm_tracing___pad2, &dumped_type_params[8], target);
    len += dump_long_long_int_from_mem(arm_tracing_st_size, &dumped_type_params[9], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_blksize, &dumped_type_params[10], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_st_blocks, &dumped_type_params[11], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_atime, &dumped_type_params[12], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_atime_nsec, &dumped_type_params[13], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_mtime, &dumped_type_params[14], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_mtime_nsec, &dumped_type_params[15], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_ctime, &dumped_type_params[16], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_ctime_nsec, &dumped_type_params[17], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_st_ino, &dumped_type_params[18], target);
  }

  *dumped_params = copy_params(dumped_type_params, 19, &len);
  free_dumped_params(dumped_type_params, 19);
  return len;
}

int dump_unsigned_int(unsigned int value, char **param_str)
{
  int len = dump_generic(param_str, NUM_CHARS_UINT, "%u", value);
  return len;
}

int dump_oabi_epoll_event(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_events = addr;
  unsigned int arm_tracing_data = addr+4;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_events, &dumped_type_params[0], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_data, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_short_unsigned_int_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_USHORT);
  int snprintf_n_read = dump_generic(param_str, NUM_CHARS_USHORT, "%hu", *value);
  free(value);
  return snprintf_n_read;
}

int dump_short_int_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_SHORT);
  int snprintf_n_read = dump_generic(param_str, NUM_CHARS_SHORT, "%hi", *value);
  free(value);
  return snprintf_n_read;
}

int dump_oabi_sembuf(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_sem_num = addr;
  unsigned int arm_tracing_sem_op = addr+2;
  unsigned int arm_tracing_sem_flg = addr+4;
  unsigned int arm_tracing___pad = addr+6;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_short_unsigned_int_from_mem(arm_tracing_sem_num, &dumped_type_params[0], target);
    len += dump_short_int_from_mem(arm_tracing_sem_op, &dumped_type_params[1], target);
    len += dump_short_int_from_mem(arm_tracing_sem_flg, &dumped_type_params[2], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing___pad, &dumped_type_params[3], target);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_long_int_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_LONG);
  int snprintf_n_read = dump_generic(param_str, NUM_CHARS_LONG, "%li", *value);
  free(value);
  return snprintf_n_read;
}

int dump_timespec(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_tv_sec = addr;
  unsigned int arm_tracing_tv_nsec = addr+4;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_int_from_mem(arm_tracing_tv_sec, &dumped_type_params[0], target);
    len += dump_long_int_from_mem(arm_tracing_tv_nsec, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_long_int(unsigned int value, char **param_str)
{
  int len = dump_generic(param_str, NUM_CHARS_LONG, "%li", value);
  return len;
}

int dump_char_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_CHAR);
  int snprintf_n_read = dump_generic(param_str, NUM_CHARS_CHAR, "%c", *value);
  free(value);
  return snprintf_n_read;
}

int dump_sockaddr(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_sa_family = addr;
  unsigned int arm_tracing_sa_data = addr+2;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_short_unsigned_int_from_mem(arm_tracing_sa_family, &dumped_type_params[0], target);
    len += dump_char_from_mem(arm_tracing_sa_data, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_iovec(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_iov_base = addr;
  unsigned int arm_tracing_iov_len = addr+4;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  arm_tracing_iov_base = read_ptr_from_mem(arm_tracing_iov_base, target);
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_iov_base, &dumped_type_params[0]);
    len += dump_unsigned_int_from_mem(arm_tracing_iov_len, &dumped_type_params[1], target);
    *dumped_params = copy_params(dumped_type_params, 2, &len);
    free_dumped_params(dumped_type_params, 2);
    return len;
  }

  if (depth >= 1)
  {
    len += dump_n_bytes_from_mem(arm_tracing_iov_base, &dumped_type_params[0], target, 256);
    len += dump_unsigned_int_from_mem(arm_tracing_iov_len, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_msghdr(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_msg_name = addr;
  unsigned int arm_tracing_msg_namelen = addr+4;
  unsigned int arm_tracing_msg_iov = addr+8;
  unsigned int arm_tracing_msg_iovlen = addr+12;
  unsigned int arm_tracing_msg_control = addr+16;
  unsigned int arm_tracing_msg_controllen = addr+20;
  unsigned int arm_tracing_msg_flags = addr+24;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(7 * (sizeof(char *)));
  arm_tracing_msg_name = read_ptr_from_mem(arm_tracing_msg_name, target);
  arm_tracing_msg_iov = read_ptr_from_mem(arm_tracing_msg_iov, target);
  arm_tracing_msg_control = read_ptr_from_mem(arm_tracing_msg_control, target);
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_msg_name, &dumped_type_params[0]);
    len += dump_int_from_mem(arm_tracing_msg_namelen, &dumped_type_params[1], target);
    len += dump_ptr(arm_tracing_msg_iov, &dumped_type_params[2]);
    len += dump_unsigned_int_from_mem(arm_tracing_msg_iovlen, &dumped_type_params[3], target);
    len += dump_ptr(arm_tracing_msg_control, &dumped_type_params[4]);
    len += dump_unsigned_int_from_mem(arm_tracing_msg_controllen, &dumped_type_params[5], target);
    len += dump_unsigned_int_from_mem(arm_tracing_msg_flags, &dumped_type_params[6], target);
    *dumped_params = copy_params(dumped_type_params, 7, &len);
    free_dumped_params(dumped_type_params, 7);
    return len;
  }

  if (depth >= 1)
  {
    len += dump_n_bytes_from_mem(arm_tracing_msg_name, &dumped_type_params[0], target, 256);
    len += dump_int_from_mem(arm_tracing_msg_namelen, &dumped_type_params[1], target);
    len += dump_iovec(depth-1, arm_tracing_msg_iov, &dumped_type_params[2], target);
    len += dump_unsigned_int_from_mem(arm_tracing_msg_iovlen, &dumped_type_params[3], target);
    len += dump_n_bytes_from_mem(arm_tracing_msg_control, &dumped_type_params[4], target, 256);
    len += dump_unsigned_int_from_mem(arm_tracing_msg_controllen, &dumped_type_params[5], target);
    len += dump_unsigned_int_from_mem(arm_tracing_msg_flags, &dumped_type_params[6], target);
  }

  *dumped_params = copy_params(dumped_type_params, 7, &len);
  free_dumped_params(dumped_type_params, 7);
  return len;
}

int dump_sched_param(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_sched_priority = addr;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(1 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int_from_mem(arm_tracing_sched_priority, &dumped_type_params[0], target);
  }

  *dumped_params = copy_params(dumped_type_params, 1, &len);
  free_dumped_params(dumped_type_params, 1);
  return len;
}

int dump_siginfo(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_si_signo = addr;
  unsigned int arm_tracing_si_errno = addr+4;
  unsigned int arm_tracing_si_code = addr+8;
  unsigned int arm_tracing__sifields = addr+12;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int_from_mem(arm_tracing_si_signo, &dumped_type_params[0], target);
    len += dump_int_from_mem(arm_tracing_si_errno, &dumped_type_params[1], target);
    len += dump_int_from_mem(arm_tracing_si_code, &dumped_type_params[2], target);
    len += dump_n_bytes_from_mem(arm_tracing__sifields, &dumped_type_params[3], target, 116);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_timeval(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_tv_sec = addr;
  unsigned int arm_tracing_tv_usec = addr+4;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_int_from_mem(arm_tracing_tv_sec, &dumped_type_params[0], target);
    len += dump_long_int_from_mem(arm_tracing_tv_usec, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_rusage(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int anonymous_inner_struct_0 = addr;
  unsigned int anonymous_inner_struct_1 = addr+8;
  unsigned int arm_tracing_ru_maxrss = addr+16;
  unsigned int arm_tracing_ru_ixrss = addr+20;
  unsigned int arm_tracing_ru_idrss = addr+24;
  unsigned int arm_tracing_ru_isrss = addr+28;
  unsigned int arm_tracing_ru_minflt = addr+32;
  unsigned int arm_tracing_ru_majflt = addr+36;
  unsigned int arm_tracing_ru_nswap = addr+40;
  unsigned int arm_tracing_ru_inblock = addr+44;
  unsigned int arm_tracing_ru_oublock = addr+48;
  unsigned int arm_tracing_ru_msgsnd = addr+52;
  unsigned int arm_tracing_ru_msgrcv = addr+56;
  unsigned int arm_tracing_ru_nsignals = addr+60;
  unsigned int arm_tracing_ru_nvcsw = addr+64;
  unsigned int arm_tracing_ru_nivcsw = addr+68;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(16 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_timeval(depth, anonymous_inner_struct_0, &dumped_type_params[0], target);
    len += dump_timeval(depth, anonymous_inner_struct_1, &dumped_type_params[1], target);
    len += dump_long_int_from_mem(arm_tracing_ru_maxrss, &dumped_type_params[2], target);
    len += dump_long_int_from_mem(arm_tracing_ru_ixrss, &dumped_type_params[3], target);
    len += dump_long_int_from_mem(arm_tracing_ru_idrss, &dumped_type_params[4], target);
    len += dump_long_int_from_mem(arm_tracing_ru_isrss, &dumped_type_params[5], target);
    len += dump_long_int_from_mem(arm_tracing_ru_minflt, &dumped_type_params[6], target);
    len += dump_long_int_from_mem(arm_tracing_ru_majflt, &dumped_type_params[7], target);
    len += dump_long_int_from_mem(arm_tracing_ru_nswap, &dumped_type_params[8], target);
    len += dump_long_int_from_mem(arm_tracing_ru_inblock, &dumped_type_params[9], target);
    len += dump_long_int_from_mem(arm_tracing_ru_oublock, &dumped_type_params[10], target);
    len += dump_long_int_from_mem(arm_tracing_ru_msgsnd, &dumped_type_params[11], target);
    len += dump_long_int_from_mem(arm_tracing_ru_msgrcv, &dumped_type_params[12], target);
    len += dump_long_int_from_mem(arm_tracing_ru_nsignals, &dumped_type_params[13], target);
    len += dump_long_int_from_mem(arm_tracing_ru_nvcsw, &dumped_type_params[14], target);
    len += dump_long_int_from_mem(arm_tracing_ru_nivcsw, &dumped_type_params[15], target);
  }

  *dumped_params = copy_params(dumped_type_params, 16, &len);
  free_dumped_params(dumped_type_params, 16);
  return len;
}

int dump_itimerval(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int anonymous_inner_struct_4 = addr;
  unsigned int anonymous_inner_struct_5 = addr+8;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_timeval(depth, anonymous_inner_struct_4, &dumped_type_params[0], target);
    len += dump_timeval(depth, anonymous_inner_struct_5, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_timezone(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_tz_minuteswest = addr;
  unsigned int arm_tracing_tz_dsttime = addr+4;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int_from_mem(arm_tracing_tz_minuteswest, &dumped_type_params[0], target);
    len += dump_int_from_mem(arm_tracing_tz_dsttime, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_timex(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_modes = addr;
  unsigned int arm_tracing_offset = addr+4;
  unsigned int arm_tracing_freq = addr+8;
  unsigned int arm_tracing_maxerror = addr+12;
  unsigned int arm_tracing_esterror = addr+16;
  unsigned int arm_tracing_status = addr+20;
  unsigned int arm_tracing_constant = addr+24;
  unsigned int arm_tracing_precision = addr+28;
  unsigned int arm_tracing_tolerance = addr+32;
  unsigned int anonymous_inner_struct_10 = addr+36;
  unsigned int arm_tracing_tick = addr+44;
  unsigned int arm_tracing_ppsfreq = addr+48;
  unsigned int arm_tracing_jitter = addr+52;
  unsigned int arm_tracing_shift = addr+56;
  unsigned int arm_tracing_stabil = addr+60;
  unsigned int arm_tracing_jitcnt = addr+64;
  unsigned int arm_tracing_calcnt = addr+68;
  unsigned int arm_tracing_errcnt = addr+72;
  unsigned int arm_tracing_stbcnt = addr+76;
  unsigned int arm_tracing_tai = addr+80;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(20 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_modes, &dumped_type_params[0], target);
    len += dump_long_int_from_mem(arm_tracing_offset, &dumped_type_params[1], target);
    len += dump_long_int_from_mem(arm_tracing_freq, &dumped_type_params[2], target);
    len += dump_long_int_from_mem(arm_tracing_maxerror, &dumped_type_params[3], target);
    len += dump_long_int_from_mem(arm_tracing_esterror, &dumped_type_params[4], target);
    len += dump_int_from_mem(arm_tracing_status, &dumped_type_params[5], target);
    len += dump_long_int_from_mem(arm_tracing_constant, &dumped_type_params[6], target);
    len += dump_long_int_from_mem(arm_tracing_precision, &dumped_type_params[7], target);
    len += dump_long_int_from_mem(arm_tracing_tolerance, &dumped_type_params[8], target);
    len += dump_timeval(depth, anonymous_inner_struct_10, &dumped_type_params[9], target);
    len += dump_long_int_from_mem(arm_tracing_tick, &dumped_type_params[10], target);
    len += dump_long_int_from_mem(arm_tracing_ppsfreq, &dumped_type_params[11], target);
    len += dump_long_int_from_mem(arm_tracing_jitter, &dumped_type_params[12], target);
    len += dump_int_from_mem(arm_tracing_shift, &dumped_type_params[13], target);
    len += dump_long_int_from_mem(arm_tracing_stabil, &dumped_type_params[14], target);
    len += dump_long_int_from_mem(arm_tracing_jitcnt, &dumped_type_params[15], target);
    len += dump_long_int_from_mem(arm_tracing_calcnt, &dumped_type_params[16], target);
    len += dump_long_int_from_mem(arm_tracing_errcnt, &dumped_type_params[17], target);
    len += dump_long_int_from_mem(arm_tracing_stbcnt, &dumped_type_params[18], target);
    len += dump_int_from_mem(arm_tracing_tai, &dumped_type_params[19], target);
  }

  *dumped_params = copy_params(dumped_type_params, 20, &len);
  free_dumped_params(dumped_type_params, 20);
  return len;
}

int dump___sysctl_args(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_name = addr;
  unsigned int arm_tracing_nlen = addr+4;
  unsigned int arm_tracing_oldval = addr+8;
  unsigned int arm_tracing_oldlenp = addr+12;
  unsigned int arm_tracing_newval = addr+16;
  unsigned int arm_tracing_newlen = addr+20;
  unsigned int arm_tracing___unused = addr+24;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(7 * (sizeof(char *)));
  arm_tracing_name = read_ptr_from_mem(arm_tracing_name, target);
  arm_tracing_oldval = read_ptr_from_mem(arm_tracing_oldval, target);
  arm_tracing_oldlenp = read_ptr_from_mem(arm_tracing_oldlenp, target);
  arm_tracing_newval = read_ptr_from_mem(arm_tracing_newval, target);
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_name, &dumped_type_params[0]);
    len += dump_int_from_mem(arm_tracing_nlen, &dumped_type_params[1], target);
    len += dump_ptr(arm_tracing_oldval, &dumped_type_params[2]);
    len += dump_ptr(arm_tracing_oldlenp, &dumped_type_params[3]);
    len += dump_ptr(arm_tracing_newval, &dumped_type_params[4]);
    len += dump_unsigned_int_from_mem(arm_tracing_newlen, &dumped_type_params[5], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing___unused, &dumped_type_params[6], target);
    *dumped_params = copy_params(dumped_type_params, 7, &len);
    free_dumped_params(dumped_type_params, 7);
    return len;
  }

  if (depth >= 1)
  {
    len += dump_int_from_mem(arm_tracing_name, &dumped_type_params[0], target);
    len += dump_int_from_mem(arm_tracing_nlen, &dumped_type_params[1], target);
    len += dump_n_bytes_from_mem(arm_tracing_oldval, &dumped_type_params[2], target, 256);
    len += dump_unsigned_int_from_mem(arm_tracing_oldlenp, &dumped_type_params[3], target);
    len += dump_n_bytes_from_mem(arm_tracing_newval, &dumped_type_params[4], target, 256);
    len += dump_unsigned_int_from_mem(arm_tracing_newlen, &dumped_type_params[5], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing___unused, &dumped_type_params[6], target);
  }

  *dumped_params = copy_params(dumped_type_params, 7, &len);
  free_dumped_params(dumped_type_params, 7);
  return len;
}

int dump___user_cap_header_struct(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_version = addr;
  unsigned int arm_tracing_pid = addr+4;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_version, &dumped_type_params[0], target);
    len += dump_int_from_mem(arm_tracing_pid, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump___user_cap_data_struct(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_effective = addr;
  unsigned int arm_tracing_permitted = addr+4;
  unsigned int arm_tracing_inheritable = addr+8;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_effective, &dumped_type_params[0], target);
    len += dump_unsigned_int_from_mem(arm_tracing_permitted, &dumped_type_params[1], target);
    len += dump_unsigned_int_from_mem(arm_tracing_inheritable, &dumped_type_params[2], target);
  }

  *dumped_params = copy_params(dumped_type_params, 3, &len);
  free_dumped_params(dumped_type_params, 3);
  return len;
}

int dump_sysinfo(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_uptime = addr;
  unsigned int arm_tracing_loads = addr+4;
  unsigned int arm_tracing_totalram = addr+16;
  unsigned int arm_tracing_freeram = addr+20;
  unsigned int arm_tracing_sharedram = addr+24;
  unsigned int arm_tracing_bufferram = addr+28;
  unsigned int arm_tracing_totalswap = addr+32;
  unsigned int arm_tracing_freeswap = addr+36;
  unsigned int arm_tracing_procs = addr+40;
  unsigned int arm_tracing_pad = addr+42;
  unsigned int arm_tracing_totalhigh = addr+44;
  unsigned int arm_tracing_freehigh = addr+48;
  unsigned int arm_tracing_mem_unit = addr+52;
  unsigned int arm_tracing__f = addr+56;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(14 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_int_from_mem(arm_tracing_uptime, &dumped_type_params[0], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_loads, &dumped_type_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_totalram, &dumped_type_params[2], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_freeram, &dumped_type_params[3], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_sharedram, &dumped_type_params[4], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_bufferram, &dumped_type_params[5], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_totalswap, &dumped_type_params[6], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_freeswap, &dumped_type_params[7], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_procs, &dumped_type_params[8], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_pad, &dumped_type_params[9], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_totalhigh, &dumped_type_params[10], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_freehigh, &dumped_type_params[11], target);
    len += dump_unsigned_int_from_mem(arm_tracing_mem_unit, &dumped_type_params[12], target);
    len += dump_char_from_mem(arm_tracing__f, &dumped_type_params[13], target);
  }

  *dumped_params = copy_params(dumped_type_params, 14, &len);
  free_dumped_params(dumped_type_params, 14);
  return len;
}

int dump_sigset_t(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_sig = addr;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(1 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int_from_mem(arm_tracing_sig, &dumped_type_params[0], target);
  }

  *dumped_params = copy_params(dumped_type_params, 1, &len);
  free_dumped_params(dumped_type_params, 1);
  return len;
}

int dump_sigaction(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_sa_handler = addr;
  unsigned int arm_tracing_sa_flags = addr+4;
  unsigned int arm_tracing_sa_restorer = addr+8;
  unsigned int arm_tracing_sa_mask = addr+12;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_ptr(arm_tracing_sa_handler, &dumped_params[0]);
    len += dump_long_unsigned_int_from_mem(arm_tracing_sa_flags, &dumped_type_params[1], target);
    len += dump_ptr(arm_tracing_sa_restorer, &dumped_params[2]);
    len += dump_sigset_t(depth, arm_tracing_sa_mask, &dumped_type_params[3], target);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_tms(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_tms_utime = addr;
  unsigned int arm_tracing_tms_stime = addr+4;
  unsigned int arm_tracing_tms_cutime = addr+8;
  unsigned int arm_tracing_tms_cstime = addr+12;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_int_from_mem(arm_tracing_tms_utime, &dumped_type_params[0], target);
    len += dump_long_int_from_mem(arm_tracing_tms_stime, &dumped_type_params[1], target);
    len += dump_long_int_from_mem(arm_tracing_tms_cutime, &dumped_type_params[2], target);
    len += dump_long_int_from_mem(arm_tracing_tms_cstime, &dumped_type_params[3], target);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_new_utsname(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_sysname = addr;
  unsigned int arm_tracing_nodename = addr+65;
  unsigned int arm_tracing_release = addr+130;
  unsigned int arm_tracing_version = addr+195;
  unsigned int arm_tracing_machine = addr+260;
  unsigned int arm_tracing_domainname = addr+325;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(6 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_char_from_mem(arm_tracing_sysname, &dumped_type_params[0], target);
    len += dump_char_from_mem(arm_tracing_nodename, &dumped_type_params[1], target);
    len += dump_char_from_mem(arm_tracing_release, &dumped_type_params[2], target);
    len += dump_char_from_mem(arm_tracing_version, &dumped_type_params[3], target);
    len += dump_char_from_mem(arm_tracing_machine, &dumped_type_params[4], target);
    len += dump_char_from_mem(arm_tracing_domainname, &dumped_type_params[5], target);
  }

  *dumped_params = copy_params(dumped_type_params, 6, &len);
  free_dumped_params(dumped_type_params, 6);
  return len;
}

int dump_rlimit(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_rlim_cur = addr;
  unsigned int arm_tracing_rlim_max = addr+4;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int_from_mem(arm_tracing_rlim_cur, &dumped_type_params[0], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_rlim_max, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_rlimit64(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_rlim_cur = addr;
  unsigned int arm_tracing_rlim_max = addr+8;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_rlim_cur, &dumped_type_params[0], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_rlim_max, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_getcpu_cache(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_blob = addr;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(1 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int_from_mem(arm_tracing_blob, &dumped_type_params[0], target);
  }

  *dumped_params = copy_params(dumped_type_params, 1, &len);
  free_dumped_params(dumped_type_params, 1);
  return len;
}

int dump_sigevent(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_sigev_value = addr;
  unsigned int arm_tracing_sigev_signo = addr+4;
  unsigned int arm_tracing_sigev_notify = addr+8;
  unsigned int arm_tracing__sigev_un = addr+12;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_n_bytes_from_mem(arm_tracing_sigev_value, &dumped_type_params[0], target, 4);
    len += dump_int_from_mem(arm_tracing_sigev_signo, &dumped_type_params[1], target);
    len += dump_int_from_mem(arm_tracing_sigev_notify, &dumped_type_params[2], target);
    len += dump_n_bytes_from_mem(arm_tracing__sigev_un, &dumped_type_params[3], target, 52);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_itimerspec(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int anonymous_inner_struct_13 = addr;
  unsigned int anonymous_inner_struct_14 = addr+8;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_timespec(depth, anonymous_inner_struct_13, &dumped_type_params[0], target);
    len += dump_timespec(depth, anonymous_inner_struct_14, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_robust_list(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_next = addr;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(1 * (sizeof(char *)));
  arm_tracing_next = read_ptr_from_mem(arm_tracing_next, target);
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_next, &dumped_type_params[0]);
    *dumped_params = copy_params(dumped_type_params, 1, &len);
    free_dumped_params(dumped_type_params, 1);
    return len;
  }

  if (depth >= 1)
  {
    len += dump_robust_list(depth-1, arm_tracing_next, &dumped_type_params[0], target);
  }

  *dumped_params = copy_params(dumped_type_params, 1, &len);
  free_dumped_params(dumped_type_params, 1);
  return len;
}

int dump_robust_list_head(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int anonymous_inner_struct_20 = addr;
  unsigned int arm_tracing_futex_offset = addr+4;
  unsigned int arm_tracing_list_op_pending = addr+8;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(3 * (sizeof(char *)));
  arm_tracing_list_op_pending = read_ptr_from_mem(arm_tracing_list_op_pending, target);
  if (depth == 0)
  {
    len += dump_robust_list(depth, anonymous_inner_struct_20, &dumped_type_params[0], target);
    len += dump_long_int_from_mem(arm_tracing_futex_offset, &dumped_type_params[1], target);
    len += dump_ptr(arm_tracing_list_op_pending, &dumped_type_params[2]);
    *dumped_params = copy_params(dumped_type_params, 3, &len);
    free_dumped_params(dumped_type_params, 3);
    return len;
  }

  if (depth >= 1)
  {
    len += dump_robust_list(depth, anonymous_inner_struct_20, &dumped_type_params[0], target);
    len += dump_long_int_from_mem(arm_tracing_futex_offset, &dumped_type_params[1], target);
    len += dump_robust_list(depth-1, arm_tracing_list_op_pending, &dumped_type_params[2], target);
  }

  *dumped_params = copy_params(dumped_type_params, 3, &len);
  free_dumped_params(dumped_type_params, 3);
  return len;
}

int dump_short_unsigned_int(unsigned int value, char **param_str)
{
  int len = dump_generic(param_str, NUM_CHARS_USHORT, "%hu", value);
  return len;
}

int dump_kexec_segment(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_buf = addr;
  unsigned int arm_tracing_bufsz = addr+4;
  unsigned int arm_tracing_mem = addr+8;
  unsigned int arm_tracing_memsz = addr+12;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  arm_tracing_buf = read_ptr_from_mem(arm_tracing_buf, target);
  if (depth == 0)
  {
    len += dump_ptr(arm_tracing_buf, &dumped_type_params[0]);
    len += dump_unsigned_int_from_mem(arm_tracing_bufsz, &dumped_type_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_mem, &dumped_type_params[2], target);
    len += dump_unsigned_int_from_mem(arm_tracing_memsz, &dumped_type_params[3], target);
    *dumped_params = copy_params(dumped_type_params, 4, &len);
    free_dumped_params(dumped_type_params, 4);
    return len;
  }

  if (depth >= 1)
  {
    len += dump_n_bytes_from_mem(arm_tracing_buf, &dumped_type_params[0], target, 256);
    len += dump_unsigned_int_from_mem(arm_tracing_bufsz, &dumped_type_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_mem, &dumped_type_params[2], target);
    len += dump_unsigned_int_from_mem(arm_tracing_memsz, &dumped_type_params[3], target);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_perf_event_attr(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_type = addr;
  unsigned int arm_tracing_size = addr+4;
  unsigned int arm_tracing_config = addr+8;
  unsigned int arm_tracing_22 = addr+16;
  unsigned int arm_tracing_sample_type = addr+24;
  unsigned int arm_tracing_read_format = addr+32;
  unsigned int arm_tracing_disabled = addr+40;
  unsigned int arm_tracing_inherit = addr+40;
  unsigned int arm_tracing_pinned = addr+40;
  unsigned int arm_tracing_exclusive = addr+40;
  unsigned int arm_tracing_exclude_user = addr+40;
  unsigned int arm_tracing_exclude_kernel = addr+40;
  unsigned int arm_tracing_exclude_hv = addr+40;
  unsigned int arm_tracing_exclude_idle = addr+40;
  unsigned int arm_tracing_mmap = addr+40;
  unsigned int arm_tracing_comm = addr+40;
  unsigned int arm_tracing_freq = addr+40;
  unsigned int arm_tracing_inherit_stat = addr+40;
  unsigned int arm_tracing_enable_on_exec = addr+40;
  unsigned int arm_tracing_task = addr+40;
  unsigned int arm_tracing_watermark = addr+40;
  unsigned int arm_tracing_precise_ip = addr+40;
  unsigned int arm_tracing_mmap_data = addr+40;
  unsigned int arm_tracing_sample_id_all = addr+40;
  unsigned int arm_tracing_exclude_host = addr+40;
  unsigned int arm_tracing_exclude_guest = addr+40;
  unsigned int arm_tracing___reserved_1 = addr+40;
  unsigned int arm_tracing_23 = addr+48;
  unsigned int arm_tracing_bp_type = addr+52;
  unsigned int arm_tracing_24 = addr+56;
  unsigned int arm_tracing_25 = addr+64;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(31 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_type, &dumped_type_params[0], target);
    len += dump_unsigned_int_from_mem(arm_tracing_size, &dumped_type_params[1], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_config, &dumped_type_params[2], target);
    len += dump_n_bytes_from_mem(arm_tracing_22, &dumped_type_params[3], target, 8);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_sample_type, &dumped_type_params[4], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_read_format, &dumped_type_params[5], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_disabled, &dumped_type_params[6], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_inherit, &dumped_type_params[7], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_pinned, &dumped_type_params[8], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_exclusive, &dumped_type_params[9], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_exclude_user, &dumped_type_params[10], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_exclude_kernel, &dumped_type_params[11], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_exclude_hv, &dumped_type_params[12], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_exclude_idle, &dumped_type_params[13], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_mmap, &dumped_type_params[14], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_comm, &dumped_type_params[15], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_freq, &dumped_type_params[16], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_inherit_stat, &dumped_type_params[17], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_enable_on_exec, &dumped_type_params[18], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_task, &dumped_type_params[19], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_watermark, &dumped_type_params[20], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_precise_ip, &dumped_type_params[21], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_mmap_data, &dumped_type_params[22], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_sample_id_all, &dumped_type_params[23], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_exclude_host, &dumped_type_params[24], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_exclude_guest, &dumped_type_params[25], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing___reserved_1, &dumped_type_params[26], target);
    len += dump_n_bytes_from_mem(arm_tracing_23, &dumped_type_params[27], target, 4);
    len += dump_unsigned_int_from_mem(arm_tracing_bp_type, &dumped_type_params[28], target);
    len += dump_n_bytes_from_mem(arm_tracing_24, &dumped_type_params[29], target, 8);
    len += dump_n_bytes_from_mem(arm_tracing_25, &dumped_type_params[30], target, 8);
  }

  *dumped_params = copy_params(dumped_type_params, 31, &len);
  free_dumped_params(dumped_type_params, 31);
  return len;
}

int dump_unsigned_char_from_mem(unsigned int addr, char **param_str, struct target *target)
{
  unsigned int *value = get_address_value(target, addr, SIZE_OF_CHAR);
  int snprintf_n_read = dump_generic(param_str, NUM_CHARS_CHAR, "%hhu", *value);
  free(value);
  return snprintf_n_read;
}

int dump_mmap_arg_struct(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_addr = addr;
  unsigned int arm_tracing_len = addr+4;
  unsigned int arm_tracing_prot = addr+8;
  unsigned int arm_tracing_flags = addr+12;
  unsigned int arm_tracing_fd = addr+16;
  unsigned int arm_tracing_offset = addr+20;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(6 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int_from_mem(arm_tracing_addr, &dumped_type_params[0], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_len, &dumped_type_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_prot, &dumped_type_params[2], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_flags, &dumped_type_params[3], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_fd, &dumped_type_params[4], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_offset, &dumped_type_params[5], target);
  }

  *dumped_params = copy_params(dumped_type_params, 6, &len);
  free_dumped_params(dumped_type_params, 6);
  return len;
}

int dump_stat(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_st_dev = addr;
  unsigned int arm_tracing_st_ino = addr+4;
  unsigned int arm_tracing_st_mode = addr+8;
  unsigned int arm_tracing_st_nlink = addr+10;
  unsigned int arm_tracing_st_uid = addr+12;
  unsigned int arm_tracing_st_gid = addr+14;
  unsigned int arm_tracing_st_rdev = addr+16;
  unsigned int arm_tracing_st_size = addr+20;
  unsigned int arm_tracing_st_blksize = addr+24;
  unsigned int arm_tracing_st_blocks = addr+28;
  unsigned int arm_tracing_st_atime = addr+32;
  unsigned int arm_tracing_st_atime_nsec = addr+36;
  unsigned int arm_tracing_st_mtime = addr+40;
  unsigned int arm_tracing_st_mtime_nsec = addr+44;
  unsigned int arm_tracing_st_ctime = addr+48;
  unsigned int arm_tracing_st_ctime_nsec = addr+52;
  unsigned int arm_tracing___unused4 = addr+56;
  unsigned int arm_tracing___unused5 = addr+60;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(18 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_dev, &dumped_type_params[0], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_ino, &dumped_type_params[1], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_st_mode, &dumped_type_params[2], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_st_nlink, &dumped_type_params[3], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_st_uid, &dumped_type_params[4], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_st_gid, &dumped_type_params[5], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_rdev, &dumped_type_params[6], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_size, &dumped_type_params[7], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_blksize, &dumped_type_params[8], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_blocks, &dumped_type_params[9], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_atime, &dumped_type_params[10], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_atime_nsec, &dumped_type_params[11], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_mtime, &dumped_type_params[12], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_mtime_nsec, &dumped_type_params[13], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_ctime, &dumped_type_params[14], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_ctime_nsec, &dumped_type_params[15], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing___unused4, &dumped_type_params[16], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing___unused5, &dumped_type_params[17], target);
  }

  *dumped_params = copy_params(dumped_type_params, 18, &len);
  free_dumped_params(dumped_type_params, 18);
  return len;
}

int dump_stat64(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_st_dev = addr;
  unsigned int arm_tracing___pad0 = addr+8;
  unsigned int arm_tracing___st_ino = addr+12;
  unsigned int arm_tracing_st_mode = addr+16;
  unsigned int arm_tracing_st_nlink = addr+20;
  unsigned int arm_tracing_st_uid = addr+24;
  unsigned int arm_tracing_st_gid = addr+28;
  unsigned int arm_tracing_st_rdev = addr+32;
  unsigned int arm_tracing___pad3 = addr+40;
  unsigned int arm_tracing_st_size = addr+48;
  unsigned int arm_tracing_st_blksize = addr+56;
  unsigned int arm_tracing_st_blocks = addr+64;
  unsigned int arm_tracing_st_atime = addr+72;
  unsigned int arm_tracing_st_atime_nsec = addr+76;
  unsigned int arm_tracing_st_mtime = addr+80;
  unsigned int arm_tracing_st_mtime_nsec = addr+84;
  unsigned int arm_tracing_st_ctime = addr+88;
  unsigned int arm_tracing_st_ctime_nsec = addr+92;
  unsigned int arm_tracing_st_ino = addr+96;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(19 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_st_dev, &dumped_type_params[0], target);
    len += dump_unsigned_char_from_mem(arm_tracing___pad0, &dumped_type_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing___st_ino, &dumped_type_params[2], target);
    len += dump_unsigned_int_from_mem(arm_tracing_st_mode, &dumped_type_params[3], target);
    len += dump_unsigned_int_from_mem(arm_tracing_st_nlink, &dumped_type_params[4], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_uid, &dumped_type_params[5], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_gid, &dumped_type_params[6], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_st_rdev, &dumped_type_params[7], target);
    len += dump_unsigned_char_from_mem(arm_tracing___pad3, &dumped_type_params[8], target);
    len += dump_long_long_int_from_mem(arm_tracing_st_size, &dumped_type_params[9], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_blksize, &dumped_type_params[10], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_st_blocks, &dumped_type_params[11], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_atime, &dumped_type_params[12], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_atime_nsec, &dumped_type_params[13], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_mtime, &dumped_type_params[14], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_mtime_nsec, &dumped_type_params[15], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_ctime, &dumped_type_params[16], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_st_ctime_nsec, &dumped_type_params[17], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_st_ino, &dumped_type_params[18], target);
  }

  *dumped_params = copy_params(dumped_type_params, 19, &len);
  free_dumped_params(dumped_type_params, 19);
  return len;
}

int dump_old_linux_dirent(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_d_ino = addr;
  unsigned int arm_tracing_d_offset = addr+4;
  unsigned int arm_tracing_d_namlen = addr+8;
  unsigned int arm_tracing_d_name = addr+10;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int_from_mem(arm_tracing_d_ino, &dumped_type_params[0], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_d_offset, &dumped_type_params[1], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_d_namlen, &dumped_type_params[2], target);
    len += dump_char_from_mem(arm_tracing_d_name, &dumped_type_params[3], target);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_linux_dirent(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_d_ino = addr;
  unsigned int arm_tracing_d_off = addr+4;
  unsigned int arm_tracing_d_reclen = addr+8;
  unsigned int arm_tracing_d_name = addr+10;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_unsigned_int_from_mem(arm_tracing_d_ino, &dumped_type_params[0], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_d_off, &dumped_type_params[1], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_d_reclen, &dumped_type_params[2], target);
    len += dump_char_from_mem(arm_tracing_d_name, &dumped_type_params[3], target);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_linux_dirent64(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_d_ino = addr;
  unsigned int arm_tracing_d_off = addr+8;
  unsigned int arm_tracing_d_reclen = addr+16;
  unsigned int arm_tracing_d_type = addr+18;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_d_ino, &dumped_type_params[0], target);
    len += dump_long_long_int_from_mem(arm_tracing_d_off, &dumped_type_params[1], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_d_reclen, &dumped_type_params[2], target);
    len += dump_unsigned_char_from_mem(arm_tracing_d_type, &dumped_type_params[3], target);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_sel_arg_struct(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_n = addr;
  unsigned int arm_tracing_inp = addr+4;
  unsigned int arm_tracing_outp = addr+8;
  unsigned int arm_tracing_exp = addr+12;
  unsigned int arm_tracing_tvp = addr+16;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(5 * (sizeof(char *)));
  arm_tracing_inp = read_ptr_from_mem(arm_tracing_inp, target);
  arm_tracing_outp = read_ptr_from_mem(arm_tracing_outp, target);
  arm_tracing_exp = read_ptr_from_mem(arm_tracing_exp, target);
  arm_tracing_tvp = read_ptr_from_mem(arm_tracing_tvp, target);
  if (depth == 0)
  {
    len += dump_long_unsigned_int_from_mem(arm_tracing_n, &dumped_type_params[0], target);
    len += dump_ptr(arm_tracing_inp, &dumped_type_params[1]);
    len += dump_ptr(arm_tracing_outp, &dumped_type_params[2]);
    len += dump_ptr(arm_tracing_exp, &dumped_type_params[3]);
    len += dump_ptr(arm_tracing_tvp, &dumped_type_params[4]);
    *dumped_params = copy_params(dumped_type_params, 5, &len);
    free_dumped_params(dumped_type_params, 5);
    return len;
  }

  if (depth >= 1)
  {
    len += dump_long_unsigned_int_from_mem(arm_tracing_n, &dumped_type_params[0], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_inp, &dumped_type_params[1], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_outp, &dumped_type_params[2], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_exp, &dumped_type_params[3], target);
    len += dump_timeval(depth-1, arm_tracing_tvp, &dumped_type_params[4], target);
  }

  *dumped_params = copy_params(dumped_type_params, 5, &len);
  free_dumped_params(dumped_type_params, 5);
  return len;
}

int dump_pollfd(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_fd = addr;
  unsigned int arm_tracing_events = addr+4;
  unsigned int arm_tracing_revents = addr+6;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int_from_mem(arm_tracing_fd, &dumped_type_params[0], target);
    len += dump_short_int_from_mem(arm_tracing_events, &dumped_type_params[1], target);
    len += dump_short_int_from_mem(arm_tracing_revents, &dumped_type_params[2], target);
  }

  *dumped_params = copy_params(dumped_type_params, 3, &len);
  free_dumped_params(dumped_type_params, 3);
  return len;
}

int dump_utimbuf(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_actime = addr;
  unsigned int arm_tracing_modtime = addr+4;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_int_from_mem(arm_tracing_actime, &dumped_type_params[0], target);
    len += dump_long_int_from_mem(arm_tracing_modtime, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump___kernel_fsid_t(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_val = addr;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(1 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int_from_mem(arm_tracing_val, &dumped_type_params[0], target);
  }

  *dumped_params = copy_params(dumped_type_params, 1, &len);
  free_dumped_params(dumped_type_params, 1);
  return len;
}

int dump_statfs(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_f_type = addr;
  unsigned int arm_tracing_f_bsize = addr+4;
  unsigned int arm_tracing_f_blocks = addr+8;
  unsigned int arm_tracing_f_bfree = addr+12;
  unsigned int arm_tracing_f_bavail = addr+16;
  unsigned int arm_tracing_f_files = addr+20;
  unsigned int arm_tracing_f_ffree = addr+24;
  unsigned int arm_tracing_f_fsid = addr+28;
  unsigned int arm_tracing_f_namelen = addr+36;
  unsigned int arm_tracing_f_frsize = addr+40;
  unsigned int arm_tracing_f_flags = addr+44;
  unsigned int arm_tracing_f_spare = addr+48;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(12 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_f_type, &dumped_type_params[0], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_bsize, &dumped_type_params[1], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_blocks, &dumped_type_params[2], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_bfree, &dumped_type_params[3], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_bavail, &dumped_type_params[4], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_files, &dumped_type_params[5], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_ffree, &dumped_type_params[6], target);
    len += dump___kernel_fsid_t(depth, arm_tracing_f_fsid, &dumped_type_params[7], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_namelen, &dumped_type_params[8], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_frsize, &dumped_type_params[9], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_flags, &dumped_type_params[10], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_spare, &dumped_type_params[11], target);
  }

  *dumped_params = copy_params(dumped_type_params, 12, &len);
  free_dumped_params(dumped_type_params, 12);
  return len;
}

int dump_statfs64(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_f_type = addr;
  unsigned int arm_tracing_f_bsize = addr+4;
  unsigned int arm_tracing_f_blocks = addr+8;
  unsigned int arm_tracing_f_bfree = addr+16;
  unsigned int arm_tracing_f_bavail = addr+24;
  unsigned int arm_tracing_f_files = addr+32;
  unsigned int arm_tracing_f_ffree = addr+40;
  unsigned int arm_tracing_f_fsid = addr+48;
  unsigned int arm_tracing_f_namelen = addr+56;
  unsigned int arm_tracing_f_frsize = addr+60;
  unsigned int arm_tracing_f_flags = addr+64;
  unsigned int arm_tracing_f_spare = addr+68;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(12 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_f_type, &dumped_type_params[0], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_bsize, &dumped_type_params[1], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_f_blocks, &dumped_type_params[2], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_f_bfree, &dumped_type_params[3], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_f_bavail, &dumped_type_params[4], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_f_files, &dumped_type_params[5], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_f_ffree, &dumped_type_params[6], target);
    len += dump___kernel_fsid_t(depth, arm_tracing_f_fsid, &dumped_type_params[7], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_namelen, &dumped_type_params[8], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_frsize, &dumped_type_params[9], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_flags, &dumped_type_params[10], target);
    len += dump_unsigned_int_from_mem(arm_tracing_f_spare, &dumped_type_params[11], target);
  }

  *dumped_params = copy_params(dumped_type_params, 12, &len);
  free_dumped_params(dumped_type_params, 12);
  return len;
}

int dump_ustat(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_f_tfree = addr;
  unsigned int arm_tracing_f_tinode = addr+4;
  unsigned int arm_tracing_f_fname = addr+8;
  unsigned int arm_tracing_f_fpack = addr+14;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int_from_mem(arm_tracing_f_tfree, &dumped_type_params[0], target);
    len += dump_long_unsigned_int_from_mem(arm_tracing_f_tinode, &dumped_type_params[1], target);
    len += dump_char_from_mem(arm_tracing_f_fname, &dumped_type_params[2], target);
    len += dump_char_from_mem(arm_tracing_f_fpack, &dumped_type_params[3], target);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_epoll_event(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_events = addr;
  unsigned int arm_tracing_data = addr+8;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_unsigned_int_from_mem(arm_tracing_events, &dumped_type_params[0], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_data, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_iocb(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_aio_data = addr;
  unsigned int arm_tracing_aio_key = addr+8;
  unsigned int arm_tracing_aio_reserved1 = addr+12;
  unsigned int arm_tracing_aio_lio_opcode = addr+16;
  unsigned int arm_tracing_aio_reqprio = addr+18;
  unsigned int arm_tracing_aio_fildes = addr+20;
  unsigned int arm_tracing_aio_buf = addr+24;
  unsigned int arm_tracing_aio_nbytes = addr+32;
  unsigned int arm_tracing_aio_offset = addr+40;
  unsigned int arm_tracing_aio_reserved2 = addr+48;
  unsigned int arm_tracing_aio_flags = addr+56;
  unsigned int arm_tracing_aio_resfd = addr+60;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(12 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_aio_data, &dumped_type_params[0], target);
    len += dump_unsigned_int_from_mem(arm_tracing_aio_key, &dumped_type_params[1], target);
    len += dump_unsigned_int_from_mem(arm_tracing_aio_reserved1, &dumped_type_params[2], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_aio_lio_opcode, &dumped_type_params[3], target);
    len += dump_short_int_from_mem(arm_tracing_aio_reqprio, &dumped_type_params[4], target);
    len += dump_unsigned_int_from_mem(arm_tracing_aio_fildes, &dumped_type_params[5], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_aio_buf, &dumped_type_params[6], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_aio_nbytes, &dumped_type_params[7], target);
    len += dump_long_long_int_from_mem(arm_tracing_aio_offset, &dumped_type_params[8], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_aio_reserved2, &dumped_type_params[9], target);
    len += dump_unsigned_int_from_mem(arm_tracing_aio_flags, &dumped_type_params[10], target);
    len += dump_unsigned_int_from_mem(arm_tracing_aio_resfd, &dumped_type_params[11], target);
  }

  *dumped_params = copy_params(dumped_type_params, 12, &len);
  free_dumped_params(dumped_type_params, 12);
  return len;
}

int dump_io_event(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_data = addr;
  unsigned int arm_tracing_obj = addr+8;
  unsigned int arm_tracing_res = addr+16;
  unsigned int arm_tracing_res2 = addr+24;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(4 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_data, &dumped_type_params[0], target);
    len += dump_long_long_unsigned_int_from_mem(arm_tracing_obj, &dumped_type_params[1], target);
    len += dump_long_long_int_from_mem(arm_tracing_res, &dumped_type_params[2], target);
    len += dump_long_long_int_from_mem(arm_tracing_res2, &dumped_type_params[3], target);
  }

  *dumped_params = copy_params(dumped_type_params, 4, &len);
  free_dumped_params(dumped_type_params, 4);
  return len;
}

int dump_long_long_unsigned_int(unsigned int value, char **param_str)
{
  int len = dump_generic(param_str, NUM_CHARS_LONG_LONG, "%llu", value);
  return len;
}

int dump_msgbuf(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_mtype = addr;
  unsigned int arm_tracing_mtext = addr+4;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_int_from_mem(arm_tracing_mtype, &dumped_type_params[0], target);
    len += dump_char_from_mem(arm_tracing_mtext, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

int dump_sembuf(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_sem_num = addr;
  unsigned int arm_tracing_sem_op = addr+2;
  unsigned int arm_tracing_sem_flg = addr+4;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(3 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_short_unsigned_int_from_mem(arm_tracing_sem_num, &dumped_type_params[0], target);
    len += dump_short_int_from_mem(arm_tracing_sem_op, &dumped_type_params[1], target);
    len += dump_short_int_from_mem(arm_tracing_sem_flg, &dumped_type_params[2], target);
  }

  *dumped_params = copy_params(dumped_type_params, 3, &len);
  free_dumped_params(dumped_type_params, 3);
  return len;
}

int dump_ipc_perm(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_key = addr;
  unsigned int arm_tracing_uid = addr+4;
  unsigned int arm_tracing_gid = addr+6;
  unsigned int arm_tracing_cuid = addr+8;
  unsigned int arm_tracing_cgid = addr+10;
  unsigned int arm_tracing_mode = addr+12;
  unsigned int arm_tracing_seq = addr+14;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(7 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_int_from_mem(arm_tracing_key, &dumped_type_params[0], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_uid, &dumped_type_params[1], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_gid, &dumped_type_params[2], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_cuid, &dumped_type_params[3], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_cgid, &dumped_type_params[4], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_mode, &dumped_type_params[5], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_seq, &dumped_type_params[6], target);
  }

  *dumped_params = copy_params(dumped_type_params, 7, &len);
  free_dumped_params(dumped_type_params, 7);
  return len;
}

int dump_shmid_ds(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int anonymous_inner_struct_32 = addr;
  unsigned int arm_tracing_shm_segsz = addr+16;
  unsigned int arm_tracing_shm_atime = addr+20;
  unsigned int arm_tracing_shm_dtime = addr+24;
  unsigned int arm_tracing_shm_ctime = addr+28;
  unsigned int arm_tracing_shm_cpid = addr+32;
  unsigned int arm_tracing_shm_lpid = addr+34;
  unsigned int arm_tracing_shm_nattch = addr+36;
  unsigned int arm_tracing_shm_unused = addr+38;
  unsigned int arm_tracing_shm_unused2 = addr+40;
  unsigned int arm_tracing_shm_unused3 = addr+44;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(11 * (sizeof(char *)));
  arm_tracing_shm_unused2 = read_ptr_from_mem(arm_tracing_shm_unused2, target);
  arm_tracing_shm_unused3 = read_ptr_from_mem(arm_tracing_shm_unused3, target);
  if (depth == 0)
  {
    len += dump_ipc_perm(depth, anonymous_inner_struct_32, &dumped_type_params[0], target);
    len += dump_int_from_mem(arm_tracing_shm_segsz, &dumped_type_params[1], target);
    len += dump_long_int_from_mem(arm_tracing_shm_atime, &dumped_type_params[2], target);
    len += dump_long_int_from_mem(arm_tracing_shm_dtime, &dumped_type_params[3], target);
    len += dump_long_int_from_mem(arm_tracing_shm_ctime, &dumped_type_params[4], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_shm_cpid, &dumped_type_params[5], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_shm_lpid, &dumped_type_params[6], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_shm_nattch, &dumped_type_params[7], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_shm_unused, &dumped_type_params[8], target);
    len += dump_ptr(arm_tracing_shm_unused2, &dumped_type_params[9]);
    len += dump_ptr(arm_tracing_shm_unused3, &dumped_type_params[10]);
    *dumped_params = copy_params(dumped_type_params, 11, &len);
    free_dumped_params(dumped_type_params, 11);
    return len;
  }

  if (depth >= 1)
  {
    len += dump_ipc_perm(depth, anonymous_inner_struct_32, &dumped_type_params[0], target);
    len += dump_int_from_mem(arm_tracing_shm_segsz, &dumped_type_params[1], target);
    len += dump_long_int_from_mem(arm_tracing_shm_atime, &dumped_type_params[2], target);
    len += dump_long_int_from_mem(arm_tracing_shm_dtime, &dumped_type_params[3], target);
    len += dump_long_int_from_mem(arm_tracing_shm_ctime, &dumped_type_params[4], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_shm_cpid, &dumped_type_params[5], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_shm_lpid, &dumped_type_params[6], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_shm_nattch, &dumped_type_params[7], target);
    len += dump_short_unsigned_int_from_mem(arm_tracing_shm_unused, &dumped_type_params[8], target);
    len += dump_n_bytes_from_mem(arm_tracing_shm_unused2, &dumped_type_params[9], target, 256);
    len += dump_n_bytes_from_mem(arm_tracing_shm_unused3, &dumped_type_params[10], target, 256);
  }

  *dumped_params = copy_params(dumped_type_params, 11, &len);
  free_dumped_params(dumped_type_params, 11);
  return len;
}

int dump_mq_attr(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int arm_tracing_mq_flags = addr;
  unsigned int arm_tracing_mq_maxmsg = addr+4;
  unsigned int arm_tracing_mq_msgsize = addr+8;
  unsigned int arm_tracing_mq_curmsgs = addr+12;
  unsigned int arm_tracing___reserved = addr+16;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(5 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_long_int_from_mem(arm_tracing_mq_flags, &dumped_type_params[0], target);
    len += dump_long_int_from_mem(arm_tracing_mq_maxmsg, &dumped_type_params[1], target);
    len += dump_long_int_from_mem(arm_tracing_mq_msgsize, &dumped_type_params[2], target);
    len += dump_long_int_from_mem(arm_tracing_mq_curmsgs, &dumped_type_params[3], target);
    len += dump_long_int_from_mem(arm_tracing___reserved, &dumped_type_params[4], target);
  }

  *dumped_params = copy_params(dumped_type_params, 5, &len);
  free_dumped_params(dumped_type_params, 5);
  return len;
}

int dump_mmsghdr(int depth, unsigned int addr, char **dumped_params, struct target *target)
{
  char **dumped_type_params;
  unsigned int anonymous_inner_struct_33 = addr;
  unsigned int arm_tracing_msg_len = addr+28;
  int len = 0;
  if (depth < 0)
  {
    *dumped_params = malloc(0);
    return len;
  }

  dumped_type_params = malloc(2 * (sizeof(char *)));
  if (depth >= 0)
  {
    len += dump_msghdr(depth, anonymous_inner_struct_33, &dumped_type_params[0], target);
    len += dump_unsigned_int_from_mem(arm_tracing_msg_len, &dumped_type_params[1], target);
  }

  *dumped_params = copy_params(dumped_type_params, 2, &len);
  free_dumped_params(dumped_type_params, 2);
  return len;
}

