#ifndef __ASM_H__
#define __ASM_H__


extern u64 get_cr0(void);
extern u64 get_cr2(void);
extern u64 get_cr3(void);
extern u64 get_cr4(void);
extern u64 get_cr8(void);
extern u64 get_cs(void);
extern u64 get_ss(void);
extern u64 hu_get_ds(void);
extern u64 get_es(void);
extern u64 hu_get_fs(void);
extern u64 get_gs(void);
extern u64 get_tr(void);
extern u64 get_dr7(void);
extern u64 get_rflags(void);
extern u64 get_ldtr(void);

extern void set_cr3(u64);
extern void set_cr4(u64 cr4);

extern void enable_vmx(void);
extern void disable_vmx(void);
extern int start_vmx(void* vmcs);
extern void stop_vmx(void);

extern int clear_vmcs(void* guest_vmcs);
extern int load_vmcs(void** guest_vmcs);
extern int write_vmcs(u64 reg_index, u64 value);
extern int read_vmcs(u64 reg_index, u64* value);

extern u64 cu_read_msr(u64 msr_index);
extern int vm_launch(void);
extern u64 calc_vm_exit_callback_addr(u64 error);
extern void vm_exit_callback_stub(void);
extern void do_invd(void);
extern void pause_loop(void);
extern void restore_context_from_stack(u64 stack_addr);

#endif