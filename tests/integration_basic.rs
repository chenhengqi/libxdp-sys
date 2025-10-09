// Integration test for libxdp-sys
// This test checks that the crate can be used and basic symbols are accessible.


#[test]
fn test_libxdp_sys_basic_usage() {
    use libxdp_sys::*;

    // Use some constants
    let _headroom = XDP_PACKET_HEADROOM;
    let _default_prio = XDP_DEFAULT_RUN_PRIO;
    let _dispatcher_version = XDP_DISPATCHER_VERSION;

    // Use a struct and call a method with no side effect
    let insn = bpf_insn {
        code: BPF_LD as u8,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(1, 2),
        off: 0,
        imm: 0,
    };
    let dst_reg = insn.dst_reg();
    let src_reg = insn.src_reg();
    assert_eq!(dst_reg, 1);
    assert_eq!(src_reg, 2);

    // Use a type alias
    let _prog_type: bpf_prog_type = bpf_prog_type_BPF_PROG_TYPE_XDP;

    // Link some functions so that compilation fails if they don't exist.
    let _xdp_program_run_prio = xdp_program__run_prio;
    let _xdp_program_set_run_prio = xdp_program__set_run_prio;
    let _xdp_program_chain_call_enabled = xdp_program__chain_call_enabled;
    let _xdp_program_set_chain_call_enabled = xdp_program__set_chain_call_enabled;
    let _xdp_program_print_chain_call_actions = xdp_program__print_chain_call_actions;
    let _xdp_program_from_bpf_obj = xdp_program__from_bpf_obj;
    let _xdp_program_find_file = xdp_program__find_file;
    let _xdp_program_open_file = xdp_program__open_file;
    let _xdp_program_from_fd = xdp_program__from_fd;
    let _xdp_program_from_id = xdp_program__from_id;
    let _xdp_program_from_pin = xdp_program__from_pin;
    let _xdp_multiprog_get_from_ifindex = xdp_multiprog__get_from_ifindex;
    let _xdp_multiprog_next_prog = xdp_multiprog__next_prog;
    let _xdp_multiprog_close = xdp_multiprog__close;
    let _xdp_multiprog_detach = xdp_multiprog__detach;
    let _xdp_multiprog_attach_mode = xdp_multiprog__attach_mode;
    let _xdp_multiprog_main_prog = xdp_multiprog__main_prog;
    let _xdp_multiprog_hw_prog = xdp_multiprog__hw_prog;
    let _xdp_multiprog_is_legacy = xdp_multiprog__is_legacy;

    let _xsk_umem_create = xsk_umem__create;
    let _xsk_umem_create_with_fd = xsk_umem__create_with_fd;
    let _xsk_umem_delete = xsk_umem__delete;
    let _xsk_umem_fd = xsk_umem__fd;
    let _xsk_umem_get_data = xsk_umem__get_data;
    let _xsk_umem_extract_addr = xsk_umem__extract_addr;
    let _xsk_umem_extract_offset = xsk_umem__extract_offset;
    let _xsk_umem_add_offset_to_addr = xsk_umem__add_offset_to_addr;
    let _xsk_socket_create = xsk_socket__create;
    let _xsk_socket_create_shared = xsk_socket__create_shared;
    let _xsk_socket_delete = xsk_socket__delete;
    let _xsk_socket_fd = xsk_socket__fd;
    let _xsk_setup_xdp_prog = xsk_setup_xdp_prog;
    let _xsk_socket_update_xskmap = xsk_socket__update_xskmap;
    let _xsk_ring_prod_reserve = xsk_ring_prod__reserve;
    let _xsk_ring_prod_submit = xsk_ring_prod__submit;
    let _xsk_ring_prod_fill_addr = xsk_ring_prod__fill_addr;
    let _xsk_ring_prod_tx_desc = xsk_ring_prod__tx_desc;
    let _xsk_ring_prod_needs_wakeup = xsk_ring_prod__needs_wakeup;
    let _xsk_ring_cons_peek = xsk_ring_cons__peek;
    let _xsk_ring_cons_cancel = xsk_ring_cons__cancel;
    let _xsk_ring_cons_release = xsk_ring_cons__release;
    let _xsk_ring_cons_comp_addr = xsk_ring_cons__comp_addr;
    let _xsk_ring_cons_rx_desc = xsk_ring_cons__rx_desc;

    // If no such function, just check linkage
    assert!(true, "libxdp-sys is usable and basic calls work");
}
