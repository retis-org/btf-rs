use std::fs::{read, read_dir};

use test_case::test_case;

use btf_rs::*;

fn bytes() -> Btf {
    Btf::from_bytes(&read("tests/data/btf/vmlinux").unwrap()).unwrap()
}

fn file() -> Btf {
    Btf::from_file("tests/data/btf/vmlinux").unwrap()
}

#[cfg(feature = "elf")]
fn elf() -> Btf {
    Btf::from_bytes(&utils::elf::extract_btf_from_file("tests/data/linux_build/vmlinux").unwrap())
        .unwrap()
}

fn split_file() -> Btf {
    let vmlinux = Btf::from_file("tests/data/btf/vmlinux").unwrap();
    Btf::from_split_file("tests/data/btf/openvswitch", &vmlinux).unwrap()
}

fn split_bytes() -> Btf {
    let vmlinux = Btf::from_bytes(&read("tests/data/btf/vmlinux").unwrap()).unwrap();
    Btf::from_split_bytes(&read("tests/data/btf/openvswitch").unwrap(), &vmlinux).unwrap()
}

#[cfg(feature = "elf")]
fn split_elf() -> Btf {
    let vmlinux = Btf::from_bytes(
        &utils::elf::extract_btf_from_file("tests/data/linux_build/vmlinux").unwrap(),
    )
    .unwrap();
    Btf::from_split_bytes(
        &utils::elf::extract_btf_from_file("tests/data/linux_build/net/openvswitch/openvswitch.ko")
            .unwrap(),
        &vmlinux,
    )
    .unwrap()
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
fn resolve_ids_by_name(btf: Btf) {
    // Resolve primitive type.
    assert_eq!(btf.resolve_ids_by_name("int").pop().unwrap(), 11);
    // Resolve typedef.
    assert_eq!(btf.resolve_ids_by_name("u64").pop().unwrap(), 58);
    // Resolve struct.
    assert_eq!(btf.resolve_ids_by_name("sk_buff").pop().unwrap(), 4984);
    // Resolve function.
    assert_eq!(btf.resolve_ids_by_name("consume_skb").pop().unwrap(), 95474);
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
fn iter_types(btf: Btf) {
    // Iterate without looping ensuring non BtfTypes return None.
    let vmalloc = match btf.resolve_types_by_name("vmalloc").unwrap().pop().unwrap() {
        Type::Func(vmalloc) => vmalloc,
        _ => panic!("Resolved type is not a function"),
    };

    let mut iter = btf.type_iter(&vmalloc);
    assert!(iter.next().is_some());
    assert!(iter.next().is_none());

    let r#type = btf.resolve_types_by_name("sk_buff").unwrap().pop().unwrap();

    let sk_buff = match r#type {
        Type::Struct(x) => x,
        _ => panic!("Resolved type is not a struct"),
    };

    let ml = sk_buff
        .members
        .iter()
        .find(|&m| btf.resolve_name(m).unwrap().eq("mac_len"));

    let types: Vec<Type> = btf
        .type_iter(ml.unwrap())
        .filter(|t| match t {
            Type::Typedef(_) | Type::Int(_) => true,
            _ => false,
        })
        .collect::<Vec<_>>();

    assert_eq!(types.len(), 2);
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
fn resolve_types_by_name(btf: Btf) {
    let types = btf.resolve_types_by_name("consume_skb").unwrap();
    assert_eq!(types.len(), 1);
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
fn resolve_types_by_name_unknown(btf: Btf) {
    assert!(btf
        .resolve_types_by_name("not_a_known_function")
        .unwrap()
        .is_empty());
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
fn check_resolved_type(btf: Btf) {
    let mut r#type = btf.resolve_types_by_name("sk_buff").unwrap();

    match r#type.pop().unwrap() {
        Type::Struct(_) => (),
        _ => panic!("Resolved type is not a struct"),
    }
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
fn bijection(btf: Btf) {
    let func = match btf.resolve_types_by_name("vmalloc").unwrap().pop().unwrap() {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(btf.resolve_name(&func).unwrap(), "vmalloc");

    let func_id = btf.resolve_ids_by_name("vmalloc").pop().unwrap();
    let func = match btf.resolve_type_by_id(func_id).unwrap() {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(btf.resolve_name(&func).unwrap(), "vmalloc");
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
fn resolve_function(btf: Btf) {
    let func = match btf
        .resolve_types_by_name("kfree_skb_reason")
        .unwrap()
        .pop()
        .unwrap()
    {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert!(func.is_static());
    assert!(!func.is_global());
    assert!(!func.is_extern());

    let proto = match btf.resolve_chained_type(&func).unwrap() {
        Type::FuncProto(proto) => proto,
        _ => panic!("Resolved type is not a function proto"),
    };

    assert_eq!(proto.parameters.len(), 2);
    assert_eq!(btf.resolve_name(&proto.parameters[0]).unwrap(), "skb");
    assert!(!proto.parameters[0].is_variadic());
    assert_eq!(btf.resolve_name(&proto.parameters[1]).unwrap(), "reason");
    assert!(!proto.parameters[1].is_variadic());

    match btf.resolve_type_by_id(proto.return_type_id()).unwrap() {
        Type::Void => (),
        _ => panic!("Resolved type is not void"),
    }

    let ptr = match btf.resolve_chained_type(&proto.parameters[0]).unwrap() {
        Type::Ptr(ptr) => ptr,
        _ => panic!("Resolved type is not a pointer"),
    };

    match btf.resolve_chained_type(&proto.parameters[1]).unwrap() {
        Type::Enum(_) => (),
        _ => panic!("Resolved type is not an enum"),
    }

    let r#struct = match btf.resolve_chained_type(&ptr).unwrap() {
        Type::Struct(r#struct) => r#struct,
        _ => panic!("Resolved type is not a struct"),
    };

    assert_eq!(btf.resolve_name(&r#struct).unwrap(), "sk_buff");
    assert_eq!(r#struct.size(), 232);
    assert_eq!(r#struct.members.len(), 28);

    assert_eq!(btf.resolve_name(&r#struct.members[25]).unwrap(), "truesize");

    let arg = match btf.resolve_chained_type(&r#struct.members[25]).unwrap() {
        Type::Int(int) => int,
        _ => panic!("Resolved type is not an integer"),
    };

    assert_eq!(btf.resolve_name(&arg).unwrap(), "unsigned int");
    assert!(!arg.is_signed());
    assert!(!arg.is_char());
    assert!(!arg.is_bool());
}

#[test]
fn wrong_file() {
    assert!(Btf::from_file("/does/not/exist").is_err());
}

#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
fn resolve_split_struct(btf: Btf) {
    let r#struct = btf
        .resolve_types_by_name("datapath")
        .unwrap()
        .pop()
        .unwrap();
    let expected = &[
        "rcu",
        "list_node",
        "table",
        "ports",
        "stats_percpu",
        "net",
        "user_features",
        "max_headroom",
        "meter_tbl",
        "upcall_portids",
    ];
    let r#struct = match r#struct {
        Type::Struct(r#struct) => r#struct,
        _ => panic!("Resolved type is not a struct"),
    };
    for (i, member) in r#struct.members.iter().enumerate() {
        let name = btf.resolve_name(member);
        assert!(name.is_ok());
        assert!(name.unwrap().eq(expected[i]));
    }

    let arg = match btf.resolve_chained_type(&r#struct.members[2]).unwrap() {
        Type::Struct(s) => s,
        _ => panic!("Resolved type is not an integer"),
    };
    assert_eq!(btf.resolve_name(&arg).unwrap(), "flow_table");
    assert_eq!(arg.members.len(), 7);
}

#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
fn resolve_split_func(btf: Btf) {
    // Resolve the following function:
    // static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
    // 				  const struct sw_flow_key *key,
    // 				  const struct dp_upcall_info *upcall_info,
    // 				  uint32_t cutlen)

    let func = match btf
        .resolve_types_by_name("queue_userspace_packet")
        .unwrap()
        .pop()
        .unwrap()
    {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert!(func.is_static());
    assert!(!func.is_global());
    assert!(!func.is_extern());

    let proto = match btf.resolve_chained_type(&func).unwrap() {
        Type::FuncProto(proto) => proto,
        _ => panic!("Resolved type is not a function proto"),
    };

    assert_eq!(proto.parameters.len(), 5);
    assert_eq!(btf.resolve_name(&proto.parameters[0]).unwrap(), "dp");
    assert!(!proto.parameters[0].is_variadic());
    assert_eq!(btf.resolve_name(&proto.parameters[1]).unwrap(), "skb");
    assert!(!proto.parameters[1].is_variadic());

    match btf.resolve_type_by_id(proto.return_type_id()).unwrap() {
        Type::Int(_) => (),
        _ => panic!("Resolved type is not int"),
    }

    let ptr0 = match btf.resolve_chained_type(&proto.parameters[0]).unwrap() {
        Type::Ptr(ptr) => ptr,
        _ => panic!("Resolved type is not a pointer"),
    };

    let ptr1 = match btf.resolve_chained_type(&proto.parameters[1]).unwrap() {
        Type::Ptr(ptr) => ptr,
        _ => panic!("Resolved type is not a pointer"),
    };

    let struct0 = match btf.resolve_chained_type(&ptr0).unwrap() {
        Type::Struct(r#struct) => r#struct,
        _ => panic!("Resolved type is not a struct"),
    };

    let struct1 = match btf.resolve_chained_type(&ptr1).unwrap() {
        Type::Struct(r#struct) => r#struct,
        _ => panic!("Resolved type is not a struct"),
    };

    assert_eq!(btf.resolve_name(&struct0).unwrap(), "datapath");
    assert_eq!(struct0.size(), 136);
    assert_eq!(struct0.members.len(), 10);

    assert_eq!(btf.resolve_name(&struct1).unwrap(), "sk_buff");
    assert_eq!(struct1.size(), 232);
    assert_eq!(struct1.members.len(), 28);
}

#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
#[cfg(feature = "regex")]
fn resolve_regex(btf: Btf) {
    use std::collections::HashSet;

    // Look for drop reason enums:
    // - skb_drop_reason
    // - mac80211_drop_reason
    // - ovs_drop_reason
    let re = regex::Regex::new(r"^[[:alnum:]]+_drop_reason$").unwrap();
    let ids = btf.resolve_ids_by_regex(&re);
    assert_eq!(ids.len(), 3);

    let types = btf.resolve_types_by_regex(&re).unwrap();
    assert_eq!(types.len(), 3);

    let mut reasons = HashSet::from(["ovs_drop_reason", "mac80211_drop_reason", "skb_drop_reason"]);
    let get_enum_name = |r#type: &Type| {
        let r#enum = match r#type {
            Type::Enum(r#enum) => r#enum,
            _ => panic!("Type is not an enum"),
        };
        btf.resolve_name(r#enum).unwrap()
    };
    types.iter().for_each(|t| {
        assert!(reasons.remove(get_enum_name(t).as_str()));
    });
    assert!(reasons.is_empty());
}

#[test]
#[cfg_attr(not(feature = "test_runtime"), ignore)]
fn test_split_files() {
    let vmlinux = Btf::from_file("/sys/kernel/btf/vmlinux");
    if vmlinux.is_err() {
        return;
    }
    let vmlinux = vmlinux.unwrap();

    // Try parsing some the modules found in the system.
    if let Ok(dir) = read_dir("/sys/kernel/btf") {
        for f in dir
            .filter(|f| {
                f.is_ok()
                    && f.as_ref().unwrap().path().to_str().is_some()
                    && f.as_ref().unwrap().file_name().ne("vmlinux")
            })
            .take(10)
        {
            // Share the same base for all.
            assert!(Btf::from_split_file(f.as_ref().unwrap().path(), &vmlinux).is_ok());
        }
    }
}

fn btfc_files() -> utils::collection::BtfCollection {
    let mut btfc = utils::collection::BtfCollection::from_file("tests/data/btf/vmlinux").unwrap();
    btfc.add_split_btf_from_file("tests/data/btf/openvswitch")
        .unwrap();
    btfc
}

fn btfc_bytes() -> utils::collection::BtfCollection {
    let mut btfc = utils::collection::BtfCollection::from_bytes(
        "vmlinux",
        &read("tests/data/btf/vmlinux").unwrap(),
    )
    .unwrap();
    btfc.add_split_btf_from_bytes("openvswitch", &read("tests/data/btf/openvswitch").unwrap())
        .unwrap();
    btfc
}

fn btfc_dir() -> utils::collection::BtfCollection {
    utils::collection::BtfCollection::from_dir("tests/data/btf", "vmlinux").unwrap()
}

#[cfg(feature = "elf")]
fn btfc_elf() -> utils::collection::BtfCollection {
    utils::elf::collection_from_kernel_dir("tests/data/linux_build").unwrap()
}

#[test_case(btfc_files())]
#[test_case(btfc_bytes())]
#[test_case(btfc_dir())]
#[cfg_attr(feature = "elf", test_case(btfc_elf()))]
fn btfc(btfc: utils::collection::BtfCollection) {
    // Resolve a function from vmlinux.
    let mut types = btfc.resolve_types_by_name("vmalloc").unwrap();
    let (nbtf, func) = match types.pop().unwrap() {
        (nbtf, Type::Func(func)) => (nbtf, func),
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(nbtf.resolve_name(&func).unwrap(), "vmalloc");

    let (nbtf, func_id) = btfc.resolve_ids_by_name("vmalloc").pop().unwrap();
    let func = match nbtf.resolve_type_by_id(func_id).unwrap() {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(nbtf.resolve_name(&func).unwrap(), "vmalloc");

    // Resolve a function from the openvswitch module.
    let mut types = btfc
        .resolve_types_by_name("queue_userspace_packet")
        .unwrap();
    let (nbtf, func) = match types.pop().unwrap() {
        (nbtf, Type::Func(func)) => (nbtf, func),
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(nbtf.resolve_name(&func).unwrap(), "queue_userspace_packet");

    let (nbtf, func_id) = btfc
        .resolve_ids_by_name("queue_userspace_packet")
        .pop()
        .unwrap();
    let func = match nbtf.resolve_type_by_id(func_id).unwrap() {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(nbtf.resolve_name(&func).unwrap(), "queue_userspace_packet");

    // Get NamedBtf references & resolve a function using it.
    assert!(btfc.get_named_btf("invalid_module").is_none());

    let ovs = btfc.get_named_btf("openvswitch").unwrap();
    let mut types = ovs.resolve_types_by_name("queue_userspace_packet").unwrap();
    let func = match types.pop().unwrap() {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };
    assert_eq!(ovs.resolve_name(&func).unwrap(), "queue_userspace_packet");
}

#[test_case(btfc_files())]
#[test_case(btfc_bytes())]
#[test_case(btfc_dir())]
#[cfg_attr(feature = "elf", test_case(btfc_elf()))]
#[cfg(feature = "regex")]
fn btfc_resolve_regex(btfc: utils::collection::BtfCollection) {
    use std::collections::HashSet;

    // Look for drop reason enums:
    // - skb_drop_reason
    // - mac80211_drop_reason
    // - ovs_drop_reason
    let re = regex::Regex::new(r"^[[:alnum:]]+_drop_reason$").unwrap();
    let ids = btfc.resolve_ids_by_regex(&re);
    assert_eq!(ids.len(), 3);

    let types = btfc.resolve_types_by_regex(&re).unwrap();
    assert_eq!(types.len(), 3);

    let mut reasons = HashSet::from(["ovs_drop_reason", "mac80211_drop_reason", "skb_drop_reason"]);
    let get_enum_name = |r#type: &(&utils::collection::NamedBtf, btf_rs::Type)| {
        let (nbtf, r#enum) = match r#type {
            (nbtf, Type::Enum(r#enum)) => (nbtf, r#enum),
            _ => panic!("Type is not an enum"),
        };
        nbtf.resolve_name(r#enum).unwrap()
    };
    types.iter().for_each(|t| {
        assert!(reasons.remove(get_enum_name(t).as_str()));
    });
    assert!(reasons.is_empty());
}
