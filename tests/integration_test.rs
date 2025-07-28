use std::fs::read;

use test_case::test_case;

use btf_rs::*;

fn bytes() -> Btf {
    Btf::from_bytes(&read("tests/assets/btf/vmlinux").unwrap()).unwrap()
}

fn file() -> Btf {
    Btf::from_file("tests/assets/btf/vmlinux").unwrap()
}

#[cfg(feature = "elf")]
fn elf() -> Btf {
    Btf::from_bytes(
        &utils::elf::extract_btf_from_file("tests/assets/elf/uncompressed/vmlinux").unwrap(),
    )
    .unwrap()
}

#[cfg(feature = "elf-compression")]
fn compressed_elf(alg: &str) -> Btf {
    Btf::from_bytes(
        &utils::elf::extract_btf_from_file(format!("tests/assets/elf/{alg}/vmlinux")).unwrap(),
    )
    .unwrap()
}

fn split_file() -> Btf {
    let vmlinux = Btf::from_file("tests/assets/btf/vmlinux").unwrap();
    Btf::from_split_file("tests/assets/btf/openvswitch", &vmlinux).unwrap()
}

fn split_bytes() -> Btf {
    let vmlinux = Btf::from_bytes(&read("tests/assets/btf/vmlinux").unwrap()).unwrap();
    Btf::from_split_bytes(&read("tests/assets/btf/openvswitch").unwrap(), &vmlinux).unwrap()
}

#[cfg(feature = "elf")]
fn split_elf() -> Btf {
    let vmlinux = Btf::from_bytes(
        &utils::elf::extract_btf_from_file("tests/assets/elf/uncompressed/vmlinux").unwrap(),
    )
    .unwrap();
    Btf::from_split_bytes(
        &utils::elf::extract_btf_from_file(
            "tests/assets/elf/uncompressed/kernel/net/openvswitch/openvswitch.ko",
        )
        .unwrap(),
        &vmlinux,
    )
    .unwrap()
}

#[cfg(feature = "elf-compression")]
fn split_compressed_elf(alg: &str, ext: &str) -> Btf {
    let vmlinux = Btf::from_bytes(
        &utils::elf::extract_btf_from_file(format!("tests/assets/elf/{alg}/vmlinux")).unwrap(),
    )
    .unwrap();
    Btf::from_split_bytes(
        &utils::elf::extract_btf_from_file(format!(
            "tests/assets/elf/{alg}/kernel/net/openvswitch/openvswitch.ko.{ext}"
        ))
        .unwrap(),
        &vmlinux,
    )
    .unwrap()
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("bzip2+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("gzip+gzip")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("xz+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("zstd+zstd")))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("bzip2+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("gzip+gzip", "gz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("xz+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("zstd+zstd", "zst"))
)]
fn resolve_ids_by_name(btf: Btf) {
    // Resolve primitive type.
    assert_eq!(btf.resolve_ids_by_name("int").pop().unwrap(), 21);
    // Resolve typedef.
    assert_eq!(btf.resolve_ids_by_name("u64").pop().unwrap(), 36);
    // Resolve struct.
    assert_eq!(btf.resolve_ids_by_name("sk_buff").pop().unwrap(), 1768);
    // Resolve function.
    assert_eq!(btf.resolve_ids_by_name("kfree_skb").pop().unwrap(), 26250);
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("bzip2+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("gzip+gzip")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("xz+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("zstd+zstd")))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("bzip2+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("gzip+gzip", "gz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("xz+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("zstd+zstd", "zst"))
)]
fn iter_types(btf: Btf) {
    // Iterate without looping ensuring non BtfTypes return None.
    let kfree = match btf.resolve_types_by_name("kfree").unwrap().pop().unwrap() {
        Type::Func(kfree) => kfree,
        _ => panic!("Resolved type is not a function"),
    };

    let mut iter = btf.type_iter(&kfree);
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
        .filter(|t| matches!(t, Type::Typedef(_) | Type::Int(_)))
        .collect::<Vec<_>>();

    assert_eq!(types.len(), 2);
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("bzip2+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("gzip+gzip")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("xz+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("zstd+zstd")))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("bzip2+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("gzip+gzip", "gz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("xz+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("zstd+zstd", "zst"))
)]
fn resolve_types_by_name(btf: Btf) {
    let types = btf.resolve_types_by_name("kfree").unwrap();
    assert_eq!(types.len(), 1);
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("bzip2+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("gzip+gzip")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("xz+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("zstd+zstd")))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("bzip2+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("gzip+gzip", "gz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("xz+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("zstd+zstd", "zst"))
)]
fn resolve_types_by_name_unknown(btf: Btf) {
    assert!(btf
        .resolve_types_by_name("not_a_known_function")
        .unwrap()
        .is_empty());
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("bzip2+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("gzip+gzip")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("xz+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("zstd+zstd")))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("bzip2+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("gzip+gzip", "gz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("xz+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("zstd+zstd", "zst"))
)]
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
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("bzip2+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("gzip+gzip")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("xz+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("zstd+zstd")))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("bzip2+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("gzip+gzip", "gz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("xz+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("zstd+zstd", "zst"))
)]
fn bijection(btf: Btf) {
    let func = match btf.resolve_types_by_name("kfree").unwrap().pop().unwrap() {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(btf.resolve_name(&func).unwrap(), "kfree");

    let func_id = btf.resolve_ids_by_name("kfree").pop().unwrap();
    let func = match btf.resolve_type_by_id(func_id).unwrap() {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(btf.resolve_name(&func).unwrap(), "kfree");
}

#[test_case(bytes())]
#[test_case(file())]
#[cfg_attr(feature = "elf", test_case(elf()))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("bzip2+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("gzip+gzip")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("xz+xz")))]
#[cfg_attr(feature = "elf-compression", test_case(compressed_elf("zstd+zstd")))]
#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("bzip2+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("gzip+gzip", "gz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("xz+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("zstd+zstd", "zst"))
)]
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
    assert_eq!(r#struct.size(), 176);
    assert_eq!(r#struct.members.len(), 25);

    assert_eq!(btf.resolve_name(&r#struct.members[23]).unwrap(), "truesize");

    let arg = match btf.resolve_chained_type(&r#struct.members[23]).unwrap() {
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
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("bzip2+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("gzip+gzip", "gz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("xz+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("zstd+zstd", "zst"))
)]
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
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("bzip2+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("gzip+gzip", "gz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("xz+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("zstd+zstd", "zst"))
)]
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

    assert!(matches!(
        btf.resolve_chained_type(&proto.parameters[0]).unwrap(),
        Type::Ptr(_)
    ));

    let ptr1 = match btf.resolve_chained_type(&proto.parameters[1]).unwrap() {
        Type::Ptr(ptr) => ptr,
        _ => panic!("Resolved type is not a pointer"),
    };

    let r#struct = match btf.resolve_chained_type(&ptr1).unwrap() {
        Type::Struct(r#struct) => r#struct,
        _ => panic!("Resolved type is not a struct"),
    };

    assert_eq!(btf.resolve_name(&r#struct).unwrap(), "sk_buff");
    assert_eq!(r#struct.size(), 176);
    assert_eq!(r#struct.members.len(), 25);
}

#[test_case(split_file())]
#[test_case(split_bytes())]
#[cfg_attr(feature = "elf", test_case(split_elf()))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("bzip2+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("gzip+gzip", "gz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("xz+xz", "xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(split_compressed_elf("zstd+zstd", "zst"))
)]
#[cfg(feature = "regex")]
fn resolve_regex(btf: Btf) {
    use std::collections::HashSet;

    // Look for drop reason enums:
    // - skb_drop_reason
    // - ovs_drop_reason
    let re = regex::Regex::new(r"^[[:alnum:]]+_drop_reason$").unwrap();
    let ids = btf.resolve_ids_by_regex(&re);
    assert!(ids.len() >= 2);

    let types = btf
        .resolve_types_by_regex(&re)
        .unwrap()
        .into_iter()
        .filter(|t| matches!(t, Type::Enum(_)))
        .collect::<Vec<_>>();
    assert_eq!(types.len(), 2);

    let mut reasons = HashSet::from(["ovs_drop_reason", "skb_drop_reason"]);
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

fn btfc_files() -> utils::collection::BtfCollection {
    let mut btfc = utils::collection::BtfCollection::from_file("tests/assets/btf/vmlinux").unwrap();
    btfc.add_split_btf_from_file("tests/assets/btf/openvswitch")
        .unwrap();
    btfc
}

fn btfc_bytes() -> utils::collection::BtfCollection {
    let mut btfc = utils::collection::BtfCollection::from_bytes(
        "vmlinux",
        &read("tests/assets/btf/vmlinux").unwrap(),
    )
    .unwrap();
    btfc.add_split_btf_from_bytes(
        "openvswitch",
        &read("tests/assets/btf/openvswitch").unwrap(),
    )
    .unwrap();
    btfc
}

fn btfc_dir() -> utils::collection::BtfCollection {
    utils::collection::BtfCollection::from_dir("tests/assets/btf", "vmlinux").unwrap()
}

#[cfg(feature = "elf")]
fn btfc_elf() -> utils::collection::BtfCollection {
    utils::elf::collection_from_kernel_dir("tests/assets/elf/uncompressed").unwrap()
}

#[cfg(feature = "elf-compression")]
fn btfc_compressed_elf(alg: &str) -> utils::collection::BtfCollection {
    utils::elf::collection_from_kernel_dir(format!("tests/assets/elf/{alg}")).unwrap()
}

#[test_case(btfc_files())]
#[test_case(btfc_bytes())]
#[test_case(btfc_dir())]
#[cfg_attr(feature = "elf", test_case(btfc_elf()))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(btfc_compressed_elf("bzip2+xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(btfc_compressed_elf("gzip+gzip"))
)]
#[cfg_attr(feature = "elf-compression", test_case(btfc_compressed_elf("xz+xz")))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(btfc_compressed_elf("zstd+zstd"))
)]
fn btfc(btfc: utils::collection::BtfCollection) {
    // Resolve a function from vmlinux.
    let mut types = btfc.resolve_types_by_name("kfree").unwrap();
    let (nbtf, func) = match types.pop().unwrap() {
        (nbtf, Type::Func(func)) => (nbtf, func),
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(nbtf.resolve_name(&func).unwrap(), "kfree");

    let (nbtf, func_id) = btfc.resolve_ids_by_name("kfree").pop().unwrap();
    let func = match nbtf.resolve_type_by_id(func_id).unwrap() {
        Type::Func(func) => func,
        _ => panic!("Resolved type is not a function"),
    };

    assert_eq!(nbtf.resolve_name(&func).unwrap(), "kfree");

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
#[cfg_attr(
    feature = "elf-compression",
    test_case(btfc_compressed_elf("bzip2+xz"))
)]
#[cfg_attr(
    feature = "elf-compression",
    test_case(btfc_compressed_elf("gzip+gzip"))
)]
#[cfg_attr(feature = "elf-compression", test_case(btfc_compressed_elf("xz+xz")))]
#[cfg_attr(
    feature = "elf-compression",
    test_case(btfc_compressed_elf("zstd+zstd"))
)]
#[cfg(feature = "regex")]
fn btfc_resolve_regex(btfc: utils::collection::BtfCollection) {
    use std::collections::HashSet;

    // Look for drop reason enums:
    // - skb_drop_reason
    // - ovs_drop_reason
    let re = regex::Regex::new(r"^[[:alnum:]]+_drop_reason$").unwrap();
    let ids = btfc.resolve_ids_by_regex(&re);
    assert!(ids.len() >= 2);

    let types = btfc
        .resolve_types_by_regex(&re)
        .unwrap()
        .into_iter()
        .filter(|(_, t)| matches!(t, Type::Enum(_)))
        .collect::<Vec<_>>();
    assert_eq!(types.len(), 2);

    let mut reasons = HashSet::from(["ovs_drop_reason", "skb_drop_reason"]);
    let get_enum_name = |r#type: &(&utils::collection::NamedBtf, btf_rs::Type)| {
        let (nbtf, r#enum) = match r#type {
            (nbtf, Type::Enum(r#enum)) => (nbtf, r#enum),
            _ => panic!("Type is not an enum"),
        };
        let name = nbtf.resolve_name(r#enum).unwrap();
        println!("{name}");
        name
    };
    types.iter().for_each(|t| {
        assert!(reasons.remove(get_enum_name(t).as_str()));
    });
    assert!(reasons.is_empty());
}
