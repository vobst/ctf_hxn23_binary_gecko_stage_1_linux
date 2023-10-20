#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SIGSTOP 19

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int tp_sys_enter_write(struct trace_event_raw_sys_exit* tp)
{
  struct task_struct* task = NULL;
  struct pt_regs* regs = NULL;
  int argc = 0, i = 0, ret = 0;
  char buf[16] = { 0 };
  void *ip = 0;

  // only hook child and parent
  if (bpf_get_current_comm((void*)buf, sizeof(buf))) {
    bpf_printk("error: bpf_get_current_comm\n");
    return 0;
  }
  if (__builtin_memcmp(buf, "hexalinux", 9)) {
    return 0;
  }

  // get address of insn after `syscall`
  task = (struct task_struct*)bpf_get_current_task_btf();
  regs = (struct pt_regs*)bpf_task_pt_regs(task);
  ip = (void*)BPF_CORE_READ(regs, ip);

  bpf_printk("IP: 0x%lx\n", (uint64_t)ip);

  bpf_send_signal(SIGSTOP);

  // 0:  e9 fb ff ff ff          jmp    0x0
  if(bpf_probe_write_user(ip, "\xE9\xFB\xFF\xFF\xFF", 5)) {
    bpf_printk("error: bpf_probe_write_user\n");
    return 0;
  }

  bpf_printk("success: hooked return address\n");


  return 0;
}
